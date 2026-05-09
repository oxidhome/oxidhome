//! Smallest possible OxidHome plugin: logs `hello` on init and `bye`
//! on shutdown. Used by `oxidhome-core`'s Phase 2 integration test as
//! proof that the host can load a real `.wasm` component, instantiate
//! it against the WIT contract, and round-trip the logging interface.

use oxidhome_sdk::Plugin;

#[derive(Default)]
struct HelloWorld;

impl Plugin for HelloWorld {
    fn init(&mut self) -> Result<(), String> {
        // Bridge tracing → host's `logging` import so this becomes a
        // real `logging::log(info, "hello")` call across the boundary.
        // Ignoring the SetGlobalDefaultError lets the host run the
        // plugin twice in the same process during tests.
        let _ = oxidhome_sdk::logging::init();
        oxidhome_sdk::tracing::info!("hello");
        Ok(())
    }

    fn shutdown(&mut self) {
        oxidhome_sdk::tracing::info!("bye");
    }
}

oxidhome_sdk::plugin!(HelloWorld);
