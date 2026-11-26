///Shorthand for `OwnedView<ListPluginsRequestView<'static>>`.
pub type OwnedListPluginsRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ListPluginsRequestView<'static>,
>;
///Shorthand for `OwnedView<ListPluginsResponseView<'static>>`.
pub type OwnedListPluginsResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ListPluginsResponseView<'static>,
>;
///Shorthand for `OwnedView<InstallPluginRequestView<'static>>`.
pub type OwnedInstallPluginRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::InstallPluginRequestView<'static>,
>;
///Shorthand for `OwnedView<InstallPluginResponseView<'static>>`.
pub type OwnedInstallPluginResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::InstallPluginResponseView<'static>,
>;
///Shorthand for `OwnedView<StartPluginRequestView<'static>>`.
pub type OwnedStartPluginRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StartPluginRequestView<'static>,
>;
///Shorthand for `OwnedView<StartPluginResponseView<'static>>`.
pub type OwnedStartPluginResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StartPluginResponseView<'static>,
>;
///Shorthand for `OwnedView<StopPluginRequestView<'static>>`.
pub type OwnedStopPluginRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StopPluginRequestView<'static>,
>;
///Shorthand for `OwnedView<StopPluginResponseView<'static>>`.
pub type OwnedStopPluginResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StopPluginResponseView<'static>,
>;
///Shorthand for `OwnedView<UninstallPluginRequestView<'static>>`.
pub type OwnedUninstallPluginRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::UninstallPluginRequestView<'static>,
>;
///Shorthand for `OwnedView<UninstallPluginResponseView<'static>>`.
pub type OwnedUninstallPluginResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::UninstallPluginResponseView<'static>,
>;
///Shorthand for `OwnedView<SetPluginNetworkGrantRequestView<'static>>`.
pub type OwnedSetPluginNetworkGrantRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantRequestView<'static>,
>;
///Shorthand for `OwnedView<SetPluginNetworkGrantResponseView<'static>>`.
pub type OwnedSetPluginNetworkGrantResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantResponseView<'static>,
>;
///Shorthand for `OwnedView<ResetPluginNetworkGrantRequestView<'static>>`.
pub type OwnedResetPluginNetworkGrantRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ResetPluginNetworkGrantResponseView<'static>>`.
pub type OwnedResetPluginNetworkGrantResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<GetPluginDenyRequestView<'static>>`.
pub type OwnedGetPluginDenyRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyRequestView<'static>,
>;
///Shorthand for `OwnedView<GetPluginDenyResponseView<'static>>`.
pub type OwnedGetPluginDenyResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyResponseView<'static>,
>;
///Shorthand for `OwnedView<SetPluginDenyRequestView<'static>>`.
pub type OwnedSetPluginDenyRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyRequestView<'static>,
>;
///Shorthand for `OwnedView<SetPluginDenyResponseView<'static>>`.
pub type OwnedSetPluginDenyResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyResponseView<'static>,
>;
///Shorthand for `OwnedView<ResetPluginDenyRequestView<'static>>`.
pub type OwnedResetPluginDenyRequestView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyRequestView<'static>,
>;
///Shorthand for `OwnedView<ResetPluginDenyResponseView<'static>>`.
pub type OwnedResetPluginDenyResponseView = ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyResponseView<'static>,
>;
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ListPluginsResponse>
for crate::proto::oxidhome::v1::__buffa::view::ListPluginsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ListPluginsResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ListPluginsResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::InstallPluginResponse>
for crate::proto::oxidhome::v1::__buffa::view::InstallPluginResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::InstallPluginResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::InstallPluginResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::StartPluginResponse>
for crate::proto::oxidhome::v1::__buffa::view::StartPluginResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::StartPluginResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StartPluginResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::StopPluginResponse>
for crate::proto::oxidhome::v1::__buffa::view::StopPluginResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::StopPluginResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::StopPluginResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::UninstallPluginResponse>
for crate::proto::oxidhome::v1::__buffa::view::UninstallPluginResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::UninstallPluginResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::UninstallPluginResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::SetPluginNetworkGrantResponse>
for crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::SetPluginNetworkGrantResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ResetPluginNetworkGrantResponse>
for crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ResetPluginNetworkGrantResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::GetPluginDenyResponse>
for crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::GetPluginDenyResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::SetPluginDenyResponse>
for crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::SetPluginDenyResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ResetPluginDenyResponse>
for crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::proto::oxidhome::v1::ResetPluginDenyResponse>
for ::buffa::view::OwnedView<
    crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyResponseView<'static>,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
/// Full service name for this service.
pub const PLUGINS_SERVICE_SERVICE_NAME: &str = "oxidhome.v1.PluginsService";
/// Static [`Spec`](::connectrpc::Spec) for the `ListPlugins` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_LIST_PLUGINS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/ListPlugins",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `InstallPlugin` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_INSTALL_PLUGIN_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/InstallPlugin",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `StartPlugin` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_START_PLUGIN_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/StartPlugin",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `StopPlugin` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_STOP_PLUGIN_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/StopPlugin",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `UninstallPlugin` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_UNINSTALL_PLUGIN_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/UninstallPlugin",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `SetPluginNetworkGrant` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_SET_PLUGIN_NETWORK_GRANT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/SetPluginNetworkGrant",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `ResetPluginNetworkGrant` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_RESET_PLUGIN_NETWORK_GRANT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/ResetPluginNetworkGrant",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `GetPluginDeny` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_GET_PLUGIN_DENY_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/GetPluginDeny",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `SetPluginDeny` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_SET_PLUGIN_DENY_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/SetPluginDeny",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `ResetPluginDeny` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const PLUGINS_SERVICE_RESET_PLUGIN_DENY_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/oxidhome.v1.PluginsService/ResetPluginDeny",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// PluginsService — the installed-and/or-running plugin catalogue.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.9.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait PluginsService: Send + Sync + 'static {
    /// List every plugin the host knows about: entries in the
    /// installed-plugin registry PLUS any dev-time argv-started
    /// instances whose plugin id isn't in the registry
    /// (`installed = false` for those rows).
    /// Method name repeats the service noun so message names satisfy
    /// buf's standard-naming rule uniquely across services — see
    /// `InstancesService` for the same pattern.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn list_plugins<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::ListPluginsRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::ListPluginsResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Install a plugin from a local source directory. Sensitive
    /// (`plugins:install` scope) — copies operator-supplied code
    /// into `<state_dir>/plugins/<plugin_id>/`. Same shape as
    /// `POST /api/v1/plugins` on the JSON API.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn install_plugin<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::InstallPluginRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::InstallPluginResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Start a supervised instance of an installed plugin. Gated on
    /// `plugins:start`. Same shape as
    /// `POST /api/v1/plugins/{plugin_id}/start`; blocks until the
    /// instance reaches `Running` before returning.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn start_plugin<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::StartPluginRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::StartPluginResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Stop one or all running instances of a plugin. Gated on
    /// `plugins:stop`. Idempotent — returns an empty `stopped_ids`
    /// when nothing was running.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn stop_plugin<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::StopPluginRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::StopPluginResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Uninstall a plugin — removes `<state_dir>/plugins/<plugin_id>/`.
    /// Sensitive (`plugins:uninstall` scope). Refuses with FAILED_PRECONDITION
    /// if any instance of the plugin is running.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn uninstall_plugin<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::UninstallPluginRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::UninstallPluginResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Set a plugin's network grant (Phase 8.5). Every rule must lie
    /// inside one the manifest requests: a grant narrows the request,
    /// never widens it (INVALID_ARGUMENT otherwise). Running instances
    /// restart under the new grant. `policy.manage`: the owner only.
    /// Same shape as `PUT /api/v1/plugins/{plugin_id}/network-grant`.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn set_plugin_network_grant<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::SetPluginNetworkGrantResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Reset a plugin's network grant to what its manifest requests,
    /// restarting its running instances. `policy.manage`. Same shape as
    /// `DELETE /api/v1/plugins/{plugin_id}/network-grant`.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn reset_plugin_network_grant<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::ResetPluginNetworkGrantResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// A plugin's deny list (H6 slice 5), empty when the owner set none.
    /// `policy.manage`. Same shape as `GET /api/v1/plugins/{plugin_id}/deny`.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn get_plugin_deny<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::GetPluginDenyRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::GetPluginDenyResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Replace a plugin's deny list: what the plugin, or any plugin whose
    /// call reaches another, may not do (`service.call`, `state.read`,
    /// `blob.read`, `event.subscribe`), whatever its manifest grants. The
    /// plugin need not be installed; running instances apply it at once.
    /// An empty list removes it. `policy.manage`. Same shape as
    /// `PUT /api/v1/plugins/{plugin_id}/deny`.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn set_plugin_deny<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::SetPluginDenyRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::SetPluginDenyResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Remove a plugin's deny list. `policy.manage`. Same shape as
    /// `DELETE /api/v1/plugins/{plugin_id}/deny`.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn reset_plugin_deny<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::proto::oxidhome::v1::ResetPluginDenyRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::proto::oxidhome::v1::ResetPluginDenyResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait PluginsServiceExt: PluginsService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: PluginsService> PluginsServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "ListPlugins",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::ListPluginsRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::ListPluginsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.list_plugins(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::ListPluginsResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_LIST_PLUGINS_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "InstallPlugin",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::InstallPluginRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::InstallPluginRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.install_plugin(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::InstallPluginResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_INSTALL_PLUGIN_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "StartPlugin",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::StartPluginRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::StartPluginRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.start_plugin(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::StartPluginResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_START_PLUGIN_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "StopPlugin",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::StopPluginRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::StopPluginRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.stop_plugin(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::StopPluginResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_STOP_PLUGIN_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "UninstallPlugin",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::UninstallPluginRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::UninstallPluginRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.uninstall_plugin(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::UninstallPluginResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_UNINSTALL_PLUGIN_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "SetPluginNetworkGrant",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.set_plugin_network_grant(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::SetPluginNetworkGrantResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_SET_PLUGIN_NETWORK_GRANT_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "ResetPluginNetworkGrant",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.reset_plugin_network_grant(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::ResetPluginNetworkGrantResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_RESET_PLUGIN_NETWORK_GRANT_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "GetPluginDeny",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::GetPluginDenyRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.get_plugin_deny(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::GetPluginDenyResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_GET_PLUGIN_DENY_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "SetPluginDeny",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::SetPluginDenyRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.set_plugin_deny(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::SetPluginDenyResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_SET_PLUGIN_DENY_SPEC)
            .route_view(
                PLUGINS_SERVICE_SERVICE_NAME,
                "ResetPluginDeny",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::proto::oxidhome::v1::ResetPluginDenyRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.reset_plugin_deny(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::proto::oxidhome::v1::ResetPluginDenyResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(PLUGINS_SERVICE_RESET_PLUGIN_DENY_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct PluginsServiceRegisterMarker;
impl<S: PluginsService> ::connectrpc::ServiceRegister<PluginsServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as PluginsServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `PluginsService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = PluginsServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct PluginsServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: PluginsService> PluginsServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for PluginsServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: PluginsService> ::connectrpc::Dispatcher for PluginsServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("oxidhome.v1.PluginsService/")?;
        match method {
            "ListPlugins" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_LIST_PLUGINS_SPEC),
                )
            }
            "InstallPlugin" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_INSTALL_PLUGIN_SPEC),
                )
            }
            "StartPlugin" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_START_PLUGIN_SPEC),
                )
            }
            "StopPlugin" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_STOP_PLUGIN_SPEC),
                )
            }
            "UninstallPlugin" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_UNINSTALL_PLUGIN_SPEC),
                )
            }
            "SetPluginNetworkGrant" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_SET_PLUGIN_NETWORK_GRANT_SPEC),
                )
            }
            "ResetPluginNetworkGrant" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_RESET_PLUGIN_NETWORK_GRANT_SPEC),
                )
            }
            "GetPluginDeny" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_GET_PLUGIN_DENY_SPEC),
                )
            }
            "SetPluginDeny" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_SET_PLUGIN_DENY_SPEC),
                )
            }
            "ResetPluginDeny" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(PLUGINS_SERVICE_RESET_PLUGIN_DENY_SPEC),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("oxidhome.v1.PluginsService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "ListPlugins" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::ListPluginsRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::ListPluginsRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::ListPluginsRequest,
                    >::from_parts(&req, &body);
                    svc.list_plugins(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::ListPluginsResponse,
                        >(format)
                })
            }
            "InstallPlugin" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::InstallPluginRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::InstallPluginRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::InstallPluginRequest,
                    >::from_parts(&req, &body);
                    svc.install_plugin(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::InstallPluginResponse,
                        >(format)
                })
            }
            "StartPlugin" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::StartPluginRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::StartPluginRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::StartPluginRequest,
                    >::from_parts(&req, &body);
                    svc.start_plugin(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::StartPluginResponse,
                        >(format)
                })
            }
            "StopPlugin" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::StopPluginRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::StopPluginRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::StopPluginRequest,
                    >::from_parts(&req, &body);
                    svc.stop_plugin(ctx, req)
                        .await?
                        .encode::<crate::proto::oxidhome::v1::StopPluginResponse>(format)
                })
            }
            "UninstallPlugin" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::UninstallPluginRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::UninstallPluginRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::UninstallPluginRequest,
                    >::from_parts(&req, &body);
                    svc.uninstall_plugin(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::UninstallPluginResponse,
                        >(format)
                })
            }
            "SetPluginNetworkGrant" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
                    >::from_parts(&req, &body);
                    svc.set_plugin_network_grant(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::SetPluginNetworkGrantResponse,
                        >(format)
                })
            }
            "ResetPluginNetworkGrant" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
                    >::from_parts(&req, &body);
                    svc.reset_plugin_network_grant(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::ResetPluginNetworkGrantResponse,
                        >(format)
                })
            }
            "GetPluginDeny" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::GetPluginDenyRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::GetPluginDenyRequest,
                    >::from_parts(&req, &body);
                    svc.get_plugin_deny(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::GetPluginDenyResponse,
                        >(format)
                })
            }
            "SetPluginDeny" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::SetPluginDenyRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::SetPluginDenyRequest,
                    >::from_parts(&req, &body);
                    svc.set_plugin_deny(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::SetPluginDenyResponse,
                        >(format)
                })
            }
            "ResetPluginDeny" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::proto::oxidhome::v1::ResetPluginDenyRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::proto::oxidhome::v1::ResetPluginDenyRequest,
                    >::from_parts(&req, &body);
                    svc.reset_plugin_deny(ctx, req)
                        .await?
                        .encode::<
                            crate::proto::oxidhome::v1::ResetPluginDenyResponse,
                        >(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("oxidhome.v1.PluginsService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("oxidhome.v1.PluginsService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("oxidhome.v1.PluginsService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = PluginsServiceClient::new(conn, config);
/// let response = client.list_plugins(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = PluginsServiceClient::new(http, config);
/// let response = client.list_plugins(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.list_plugins(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.list_plugins(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct PluginsServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> PluginsServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the ListPlugins RPC. Sends a request to /oxidhome.v1.PluginsService/ListPlugins.
    pub async fn list_plugins(
        &self,
        request: crate::proto::oxidhome::v1::ListPluginsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ListPluginsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.list_plugins_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ListPlugins RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn list_plugins_with_options(
        &self,
        request: crate::proto::oxidhome::v1::ListPluginsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ListPluginsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_LIST_PLUGINS_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the InstallPlugin RPC. Sends a request to /oxidhome.v1.PluginsService/InstallPlugin.
    pub async fn install_plugin(
        &self,
        request: crate::proto::oxidhome::v1::InstallPluginRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::InstallPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.install_plugin_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the InstallPlugin RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn install_plugin_with_options(
        &self,
        request: crate::proto::oxidhome::v1::InstallPluginRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::InstallPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_INSTALL_PLUGIN_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the StartPlugin RPC. Sends a request to /oxidhome.v1.PluginsService/StartPlugin.
    pub async fn start_plugin(
        &self,
        request: crate::proto::oxidhome::v1::StartPluginRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::StartPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.start_plugin_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the StartPlugin RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn start_plugin_with_options(
        &self,
        request: crate::proto::oxidhome::v1::StartPluginRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::StartPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_START_PLUGIN_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the StopPlugin RPC. Sends a request to /oxidhome.v1.PluginsService/StopPlugin.
    pub async fn stop_plugin(
        &self,
        request: crate::proto::oxidhome::v1::StopPluginRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::StopPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.stop_plugin_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the StopPlugin RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn stop_plugin_with_options(
        &self,
        request: crate::proto::oxidhome::v1::StopPluginRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::StopPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_STOP_PLUGIN_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the UninstallPlugin RPC. Sends a request to /oxidhome.v1.PluginsService/UninstallPlugin.
    pub async fn uninstall_plugin(
        &self,
        request: crate::proto::oxidhome::v1::UninstallPluginRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::UninstallPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.uninstall_plugin_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the UninstallPlugin RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn uninstall_plugin_with_options(
        &self,
        request: crate::proto::oxidhome::v1::UninstallPluginRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::UninstallPluginResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_UNINSTALL_PLUGIN_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the SetPluginNetworkGrant RPC. Sends a request to /oxidhome.v1.PluginsService/SetPluginNetworkGrant.
    pub async fn set_plugin_network_grant(
        &self,
        request: crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.set_plugin_network_grant_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the SetPluginNetworkGrant RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn set_plugin_network_grant_with_options(
        &self,
        request: crate::proto::oxidhome::v1::SetPluginNetworkGrantRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::SetPluginNetworkGrantResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_SET_PLUGIN_NETWORK_GRANT_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the ResetPluginNetworkGrant RPC. Sends a request to /oxidhome.v1.PluginsService/ResetPluginNetworkGrant.
    pub async fn reset_plugin_network_grant(
        &self,
        request: crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.reset_plugin_network_grant_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ResetPluginNetworkGrant RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn reset_plugin_network_grant_with_options(
        &self,
        request: crate::proto::oxidhome::v1::ResetPluginNetworkGrantRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ResetPluginNetworkGrantResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_RESET_PLUGIN_NETWORK_GRANT_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the GetPluginDeny RPC. Sends a request to /oxidhome.v1.PluginsService/GetPluginDeny.
    pub async fn get_plugin_deny(
        &self,
        request: crate::proto::oxidhome::v1::GetPluginDenyRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.get_plugin_deny_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the GetPluginDeny RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn get_plugin_deny_with_options(
        &self,
        request: crate::proto::oxidhome::v1::GetPluginDenyRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::GetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_GET_PLUGIN_DENY_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the SetPluginDeny RPC. Sends a request to /oxidhome.v1.PluginsService/SetPluginDeny.
    pub async fn set_plugin_deny(
        &self,
        request: crate::proto::oxidhome::v1::SetPluginDenyRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.set_plugin_deny_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the SetPluginDeny RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn set_plugin_deny_with_options(
        &self,
        request: crate::proto::oxidhome::v1::SetPluginDenyRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::SetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_SET_PLUGIN_DENY_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the ResetPluginDeny RPC. Sends a request to /oxidhome.v1.PluginsService/ResetPluginDeny.
    pub async fn reset_plugin_deny(
        &self,
        request: crate::proto::oxidhome::v1::ResetPluginDenyRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.reset_plugin_deny_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ResetPluginDeny RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn reset_plugin_deny_with_options(
        &self,
        request: crate::proto::oxidhome::v1::ResetPluginDenyRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::proto::oxidhome::v1::__buffa::view::ResetPluginDenyResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                PLUGINS_SERVICE_RESET_PLUGIN_DENY_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
}
