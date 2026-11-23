//! `host-media` and `media` for streaming instances, until native media
//! pipelines exist (Phase 9).
//!
//! Linking them lets a streaming component that references the media
//! imports load; every call answers `unavailable`. No pipeline handle or
//! pipe writer is ever created, so their methods can't be reached.

use wasmtime::component::{HasSelf, Linker, Resource};

use super::state::PluginState;
use crate::host_impl::streaming_plugin::oxidhome::plugin::{host_media, media, types};
use crate::host_impl::{HostPipeWriter, HostPipelineHandle};

const UNAVAILABLE: &str = "media pipelines are not supported by this host yet";

pub(super) fn add_to_linker(linker: &mut Linker<PluginState>) -> anyhow::Result<()> {
    media::add_to_linker::<PluginState, HasSelf<PluginState>>(linker, |state| state)?;
    host_media::add_to_linker::<PluginState, HasSelf<PluginState>>(linker, |state| state)?;
    Ok(())
}

fn unavailable() -> types::Error {
    types::Error::Unavailable(UNAVAILABLE.into())
}

impl host_media::Host for PluginState {
    async fn start_pipeline(
        &mut self,
        _device: types::DeviceId,
        _pipeline: media::MediaPipeline,
    ) -> Result<Resource<HostPipelineHandle>, types::Error> {
        Err(unavailable())
    }

    async fn open_pipe(
        &mut self,
        _config: media::PluginPipeConfig,
    ) -> Result<Resource<HostPipeWriter>, types::Error> {
        Err(unavailable())
    }
}

impl media::Host for PluginState {}

impl media::HostPipelineHandle for PluginState {
    async fn stop(&mut self, _handle: Resource<HostPipelineHandle>) {}

    async fn update(
        &mut self,
        _handle: Resource<HostPipelineHandle>,
        _pipeline: media::MediaPipeline,
    ) -> Result<(), types::Error> {
        Err(unavailable())
    }

    async fn drop(&mut self, _handle: Resource<HostPipelineHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl media::HostPipeWriter for PluginState {
    async fn write(
        &mut self,
        _writer: Resource<HostPipeWriter>,
        _data: Vec<u8>,
    ) -> Result<u64, types::Error> {
        Err(unavailable())
    }

    async fn close(&mut self, _writer: Resource<HostPipeWriter>) {}

    async fn drop(&mut self, _writer: Resource<HostPipeWriter>) -> wasmtime::Result<()> {
        Ok(())
    }
}
