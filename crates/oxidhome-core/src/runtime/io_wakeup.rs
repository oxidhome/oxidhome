//! Readiness wakeups for streaming instances (Phase 8).
//!
//! A streaming plugin that keeps sockets open between calls would
//! otherwise only see what arrived on them at its next periodic `tick`.
//! While the supervisor waits between calls, it also waits on the read
//! side of the sockets the guest holds open, and runs `tick` early when
//! one of them becomes readable:
//!
//! - **What is watched:** every TCP input stream (the one
//!   `finish-connect` handed the guest) and every UDP
//!   `incoming-datagram-stream` in the instance's resource table, and
//!   every `host-network` discovery socket. Other streams (stdin,
//!   `wasi:http` bodies) are not.
//! - **Who gets it:** `streaming-plugin` / `streaming-ai-plugin`
//!   instances whose manifest sets `runtime.tick_interval_ms`. A plugin
//!   without a tick cadence is never ticked, early or not; the other
//!   worlds have no sockets.
//! - **Coalesced:** readiness is checked only while no guest call runs,
//!   so whatever arrives during one wait (one datagram or a thousand)
//!   wakes the plugin once.
//! - **Rate-bounded:** an early tick starts no sooner than
//!   [`IO_WAKE_MIN_GAP`] after the previous tick (early or periodic)
//!   returned, measured on the engine clock. A stream the plugin leaves
//!   readable (unread data, end of stream, a read side shut down) wakes
//!   it again at most that often, until it is drained or dropped.
//! - An early tick is an ordinary `tick` call: the liveness watchdog
//!   bounds it, a requested stop goes first, and events are drained
//!   after it as after any tick.
//!
//! A datagram the network policy drops on receive (its sender isn't
//! allowed) never makes the stream readable: `wasmtime-wasi` discards it
//! inside the receive that readiness waits on; a discovery socket's wait
//! discards it the same way.

use std::any::Any;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::p2::bindings::sockets::udp::IncomingDatagramStream;
use wasmtime_wasi::p2::{DynFuture, DynInputStream, Pollable as _, TcpSocket};

use super::network::DiscoverySocket;

/// Shortest time between the end of one tick and the start of an early
/// tick a readable socket triggers.
pub(crate) const IO_WAKE_MIN_GAP: Duration = Duration::from_millis(100);

/// A future that completes once any watched stream in the table is
/// readable (see the module docs). Pending forever when none is.
pub(crate) struct Readable<'a> {
    waits: Vec<DynFuture<'a>>,
}

impl Readable<'_> {
    /// Whether no stream is watched, so this never completes.
    pub(crate) fn is_empty(&self) -> bool {
        self.waits.is_empty()
    }
}

impl Future for Readable<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Every wait is polled, so each registers its waker.
        let mut ready = false;
        for wait in &mut self.waits {
            ready |= wait.as_mut().poll(cx).is_ready();
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Wait for the read side of the sockets in `table`.
pub(crate) fn readable(table: &mut ResourceTable) -> Readable<'_> {
    let tcp_inputs = tcp_input_streams(table);
    let waits = table
        .iter_mut()
        .filter_map(|(_, entry)| {
            if entry.is::<IncomingDatagramStream>() {
                let stream = entry.downcast_mut::<IncomingDatagramStream>()?;
                Some(stream.ready())
            } else if entry.is::<DiscoverySocket>() {
                let socket = entry.downcast_mut::<DiscoverySocket>()?;
                Some(socket.ready())
            } else if tcp_inputs.contains(&entry_addr(entry)) {
                let stream = entry.downcast_mut::<DynInputStream>()?;
                Some(stream.ready())
            } else {
                None
            }
        })
        .collect();
    Readable { waits }
}

/// The input streams of the TCP sockets in `table`, by entry address.
///
/// `wasmtime-wasi` stores a connected socket's input stream as a child
/// of the socket's entry, typed only as a boxed `input-stream` (stdin
/// and `wasi:http` bodies have the same type), so the socket's children
/// are what tells a TCP stream apart. The table lends children out
/// read-only; the address of the boxed entry identifies them in the
/// mutable walk.
fn tcp_input_streams(table: &mut ResourceTable) -> HashSet<usize> {
    let sockets: Vec<u32> = table
        .iter_mut()
        .filter(|(_, entry)| entry.is::<TcpSocket>())
        .map(|(rep, _)| rep)
        .collect();
    let mut inputs = HashSet::new();
    for rep in sockets {
        let Ok(children) = table.iter_children(&Resource::<TcpSocket>::new_borrow(rep)) else {
            continue;
        };
        inputs.extend(
            children
                .filter(|child| child.is::<DynInputStream>())
                .map(entry_addr),
        );
    }
    inputs
}

/// Identity of a table entry: the address of its boxed value.
fn entry_addr(entry: &(dyn Any + Send)) -> usize {
    std::ptr::from_ref(entry).cast::<()>().addr()
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use wasmtime_wasi::p2::pipe::{AsyncReadStream, ClosedInputStream};

    use super::*;

    fn poll_once(fut: &mut Readable<'_>) -> Poll<()> {
        Pin::new(fut).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn nothing_to_watch_stays_pending() {
        let mut table = ResourceTable::new();
        // A readable input stream that isn't a TCP socket's.
        let stdin: DynInputStream = Box::new(ClosedInputStream);
        table.push(stdin).unwrap();
        let mut ready = readable(&mut table);
        assert!(ready.is_empty());
        assert!(poll_once(&mut ready).is_pending());
    }

    #[tokio::test]
    async fn only_socket_children_are_watched() {
        let mut table = ResourceTable::new();
        let (_writer, reader) = tokio::io::duplex(16);
        let stream: DynInputStream = Box::new(AsyncReadStream::new(reader));
        table.push(stream).unwrap();
        assert!(tcp_input_streams(&mut table).is_empty());
        assert!(poll_once(&mut readable(&mut table)).is_pending());
    }
}
