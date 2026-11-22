//! Binary proof of WIT contract compatibility (architecture review M1).
//!
//! The manifest's `sdk_version` is a claim the plugin author writes by
//! hand; nothing ties it to the code in the `.wasm`. Every component,
//! though, carries the full type of every interface it imports and
//! exports, and `wit-bindgen` keeps the original WIT names
//! (`oxidhome:plugin/host-devices@0.1.0`). [`verify_component`] decodes
//! that type information and checks it against the host's own copy of
//! the `oxidhome:plugin` package, which `build.rs` bakes in from `wit/`.
//!
//! The check, for each item the component uses from `oxidhome:plugin`:
//!
//! - the package version must equal the host's;
//! - the interface must exist in the host's package;
//! - every function the component imports or exports from it must
//!   exist on the host's side with a structurally identical signature
//!   (parameter names and types, result type, record fields, variant
//!   cases, enum/flags members, resource identities);
//! - every function the host's `plugin` world requires the component to
//!   export must be exported, with the same signature.
//!
//! A component may import a *subset* of an interface's functions:
//! `wit-component` drops imports the guest never calls, so a plugin
//! that only logs imports only `logging`. Extra exports are ignored.
//!
//! A component that uses nothing from `oxidhome:plugin` carries no
//! proof and is refused ([`ContractError::NoContract`]); so is one whose
//! type information can't be decoded. Comparison is structural: type
//! *names* and doc comments don't matter, the canonical-ABI shape does.
//! Wasmtime's own instantiation type-check would catch most of these
//! too, but later, with an error that names a linker slot rather than
//! the contract version the plugin was built against.

use std::fmt::Write as _;
use std::sync::LazyLock;

use thiserror::Error;
use wit_parser::decoding::{DecodedWasm, decode};
use wit_parser::{
    Function, FunctionKind, Handle, InterfaceId, PackageId, Resolve, Type, TypeDefKind, TypeId,
    TypeOwner, WorldItem, WorldKey,
};

/// The host's `oxidhome:plugin` package, encoded as a binary WIT
/// package by `build.rs`.
static HOST_CONTRACT_WASM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/oxidhome-plugin-contract.wasm"));

/// Namespace and name of the contract package.
const CONTRACT_NAMESPACE: &str = "oxidhome";
const CONTRACT_NAME: &str = "plugin";
/// The world the loader instantiates components as.
const HOST_WORLD: &str = "plugin";

/// Why a component's embedded types don't prove compatibility with
/// this host's `oxidhome:plugin` contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContractError {
    #[error("could not decode the component's WIT type information: {0}")]
    Undecodable(String),
    #[error("the file is a WIT package, not a component")]
    NotAComponent,
    #[error(
        "the component uses nothing from {CONTRACT_NAMESPACE}:{CONTRACT_NAME}, so it carries no \
         proof it was built against this host's contract (oxidhome:plugin@{host})"
    )]
    NoContract { host: String },
    #[error(
        "the component was built against oxidhome:plugin@{plugin}, but this host implements \
         oxidhome:plugin@{host}; rebuild the plugin against a matching oxidhome-sdk"
    )]
    VersionMismatch { plugin: String, host: String },
    #[error(
        "the component uses interface `{interface}`, which this host's contract does not define"
    )]
    UnknownInterface { interface: String },
    #[error(
        "the component uses function `{function}` of `{interface}`, which this host's contract \
         does not define"
    )]
    UnknownFunction { interface: String, function: String },
    #[error(
        "`{item}` does not match this host's contract:\n    plugin: {plugin}\n    host:   {host}"
    )]
    SignatureMismatch {
        item: String,
        plugin: String,
        host: String,
    },
    #[error("the component does not export `{name}`, which the `{HOST_WORLD}` world requires")]
    MissingExport { name: String },
}

/// The host side of the comparison, decoded once.
struct HostContract {
    resolve: Resolve,
    package: PackageId,
}

static HOST: LazyLock<HostContract> = LazyLock::new(|| {
    match decode(HOST_CONTRACT_WASM).expect("build.rs encodes a valid WIT package") {
        DecodedWasm::WitPackage(resolve, package) => HostContract { resolve, package },
        DecodedWasm::Component(..) => unreachable!("build.rs encodes a WIT package"),
    }
});

/// Version of the `oxidhome:plugin` WIT package this host implements,
/// e.g. `0.1.0`.
#[must_use]
pub fn host_contract_version() -> String {
    let host = &*HOST;
    version_string(&host.resolve, host.package)
}

/// Check that `wasm`'s embedded WIT types match this host's
/// `oxidhome:plugin` contract. See the module docs for the rules.
///
/// # Errors
///
/// The first [`ContractError`] found.
pub fn verify_component(wasm: &[u8]) -> Result<(), ContractError> {
    let (guest, world) = match decode(wasm) {
        Ok(DecodedWasm::Component(resolve, world)) => (resolve, world),
        Ok(DecodedWasm::WitPackage(..)) => return Err(ContractError::NotAComponent),
        Err(e) => return Err(ContractError::Undecodable(format!("{e:#}"))),
    };
    let host = &*HOST;
    let host_version = version_string(&host.resolve, host.package);
    let world = &guest.worlds[world];

    let mut uses_contract = false;
    for item in world.imports.values().chain(world.exports.values()) {
        let WorldItem::Interface { id, .. } = item else {
            continue;
        };
        let Some(pkg) = guest.interfaces[*id].package else {
            continue;
        };
        let name = &guest.packages[pkg].name;
        if name.namespace != CONTRACT_NAMESPACE || name.name != CONTRACT_NAME {
            continue;
        }
        uses_contract = true;
        let plugin_version = version_string(&guest, pkg);
        if plugin_version != host_version {
            return Err(ContractError::VersionMismatch {
                plugin: plugin_version,
                host: host_version,
            });
        }
        check_interface(&guest, *id, host)?;
    }
    if !uses_contract {
        return Err(ContractError::NoContract { host: host_version });
    }

    // World-level exports (`init`, `on-event`, ...) aren't namespaced
    // by the package, so compare them against the host world by name.
    let host_world = &host.resolve.worlds[host.resolve.packages[host.package].worlds[HOST_WORLD]];
    for (key, item) in &host_world.exports {
        let WorldItem::Function(expected) = item else {
            continue;
        };
        let name = host.resolve.name_world_key(key);
        let Some(WorldItem::Function(actual)) = world.exports.get(&WorldKey::Name(name.clone()))
        else {
            return Err(ContractError::MissingExport { name });
        };
        compare_functions(&guest, actual, &host.resolve, expected, &name)?;
    }
    Ok(())
}

fn check_interface(
    guest: &Resolve,
    id: InterfaceId,
    host: &HostContract,
) -> Result<(), ContractError> {
    let iface = &guest.interfaces[id];
    let qualified = guest
        .id_of(id)
        .unwrap_or_else(|| "<anonymous interface>".to_owned());
    let host_id = iface
        .name
        .as_ref()
        .and_then(|n| host.resolve.packages[host.package].interfaces.get(n))
        .ok_or_else(|| ContractError::UnknownInterface {
            interface: qualified.clone(),
        })?;
    let host_iface = &host.resolve.interfaces[*host_id];
    for (fname, func) in &iface.functions {
        let Some(expected) = host_iface.functions.get(fname) else {
            return Err(ContractError::UnknownFunction {
                interface: qualified,
                function: fname.clone(),
            });
        };
        compare_functions(
            guest,
            func,
            &host.resolve,
            expected,
            &format!("{qualified}#{fname}"),
        )?;
    }
    Ok(())
}

fn compare_functions(
    guest: &Resolve,
    actual: &Function,
    host: &Resolve,
    expected: &Function,
    item: &str,
) -> Result<(), ContractError> {
    let plugin = render_function(guest, actual);
    let host = render_function(host, expected);
    if plugin == host {
        Ok(())
    } else {
        Err(ContractError::SignatureMismatch {
            item: item.to_owned(),
            plugin,
            host,
        })
    }
}

fn version_string(resolve: &Resolve, pkg: PackageId) -> String {
    resolve.packages[pkg]
        .name
        .version
        .as_ref()
        .map_or_else(|| "(unversioned)".to_owned(), ToString::to_string)
}

/// Canonical structural rendering of a function signature. Two
/// functions render equal iff their component-level types are equal.
fn render_function(resolve: &Resolve, func: &Function) -> String {
    let mut out = String::new();
    if matches!(
        func.kind,
        FunctionKind::AsyncFreestanding
            | FunctionKind::AsyncMethod(_)
            | FunctionKind::AsyncStatic(_)
    ) {
        out.push_str("async ");
    }
    out.push_str("func(");
    for (i, param) in func.params.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&param.name);
        out.push_str(": ");
        render_type(resolve, param.ty, &mut out);
    }
    out.push(')');
    if let Some(result) = func.result {
        out.push_str(" -> ");
        render_type(resolve, result, &mut out);
    }
    out
}

fn render_type(resolve: &Resolve, ty: Type, out: &mut String) {
    let prim = match ty {
        Type::Bool => "bool",
        Type::U8 => "u8",
        Type::U16 => "u16",
        Type::U32 => "u32",
        Type::U64 => "u64",
        Type::S8 => "s8",
        Type::S16 => "s16",
        Type::S32 => "s32",
        Type::S64 => "s64",
        Type::F32 => "f32",
        Type::F64 => "f64",
        Type::Char => "char",
        Type::String => "string",
        Type::ErrorContext => "error-context",
        Type::Id(id) => return render_def(resolve, id, out),
    };
    out.push_str(prim);
}

fn render_opt(resolve: &Resolve, ty: Option<Type>, out: &mut String) {
    match ty {
        Some(ty) => render_type(resolve, ty, out),
        None => out.push('_'),
    }
}

fn render_def(resolve: &Resolve, id: TypeId, out: &mut String) {
    match &resolve.types[id].kind {
        TypeDefKind::Type(ty) => render_type(resolve, *ty, out),
        TypeDefKind::Record(r) => {
            out.push_str("record { ");
            for f in &r.fields {
                out.push_str(&f.name);
                out.push_str(": ");
                render_type(resolve, f.ty, out);
                out.push_str(", ");
            }
            out.push('}');
        }
        TypeDefKind::Variant(v) => {
            out.push_str("variant { ");
            for c in &v.cases {
                out.push_str(&c.name);
                if let Some(ty) = c.ty {
                    out.push('(');
                    render_type(resolve, ty, out);
                    out.push(')');
                }
                out.push_str(", ");
            }
            out.push('}');
        }
        TypeDefKind::Enum(e) => {
            out.push_str("enum { ");
            for c in &e.cases {
                out.push_str(&c.name);
                out.push_str(", ");
            }
            out.push('}');
        }
        TypeDefKind::Flags(f) => {
            out.push_str("flags { ");
            for flag in &f.flags {
                out.push_str(&flag.name);
                out.push_str(", ");
            }
            out.push('}');
        }
        TypeDefKind::Resource => render_resource(resolve, id, out),
        TypeDefKind::Handle(Handle::Own(r)) => {
            out.push_str("own<");
            render_resource(resolve, *r, out);
            out.push('>');
        }
        TypeDefKind::Handle(Handle::Borrow(r)) => {
            out.push_str("borrow<");
            render_resource(resolve, *r, out);
            out.push('>');
        }
        TypeDefKind::Unknown => out.push_str("<unknown>"),
        kind => render_generic(resolve, kind, out),
    }
}

/// The parameterized type constructors (`list<T>`, `option<T>`, ...).
fn render_generic(resolve: &Resolve, kind: &TypeDefKind, out: &mut String) {
    match kind {
        TypeDefKind::Tuple(t) => {
            out.push_str("tuple<");
            for (i, ty) in t.types.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_type(resolve, *ty, out);
            }
            out.push('>');
        }
        TypeDefKind::Option(ty) => {
            out.push_str("option<");
            render_type(resolve, *ty, out);
            out.push('>');
        }
        TypeDefKind::Result(r) => {
            out.push_str("result<");
            render_opt(resolve, r.ok, out);
            out.push_str(", ");
            render_opt(resolve, r.err, out);
            out.push('>');
        }
        TypeDefKind::List(ty) => {
            out.push_str("list<");
            render_type(resolve, *ty, out);
            out.push('>');
        }
        TypeDefKind::Map(k, v) => {
            out.push_str("map<");
            render_type(resolve, *k, out);
            out.push_str(", ");
            render_type(resolve, *v, out);
            out.push('>');
        }
        TypeDefKind::FixedLengthList(ty, n) => {
            out.push_str("list<");
            render_type(resolve, *ty, out);
            let _ = write!(out, ", {n}>");
        }
        TypeDefKind::Future(ty) => {
            out.push_str("future<");
            render_opt(resolve, *ty, out);
            out.push('>');
        }
        TypeDefKind::Stream(ty) => {
            out.push_str("stream<");
            render_opt(resolve, *ty, out);
            out.push('>');
        }
        TypeDefKind::Type(_)
        | TypeDefKind::Record(_)
        | TypeDefKind::Variant(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Flags(_)
        | TypeDefKind::Resource
        | TypeDefKind::Handle(_)
        | TypeDefKind::Unknown => unreachable!("handled by render_def"),
    }
}

/// Resources are nominal: render the defining interface and name,
/// following `type x = y` aliases to the definition.
fn render_resource(resolve: &Resolve, mut id: TypeId, out: &mut String) {
    while let TypeDefKind::Type(Type::Id(next)) = resolve.types[id].kind {
        id = next;
    }
    let def = &resolve.types[id];
    out.push_str("resource ");
    match def.owner {
        TypeOwner::Interface(iface) => {
            out.push_str(&resolve.id_of(iface).unwrap_or_default());
            out.push('.');
        }
        TypeOwner::World(world) => {
            out.push_str(&resolve.worlds[world].name);
            out.push('.');
        }
        TypeOwner::None => {}
    }
    out.push_str(def.name.as_deref().unwrap_or("<anonymous>"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_contract_decodes_with_plugin_world() {
        let host = &*HOST;
        let pkg = &host.resolve.packages[host.package];
        assert_eq!(pkg.name.namespace, CONTRACT_NAMESPACE);
        assert_eq!(pkg.name.name, CONTRACT_NAME);
        assert!(pkg.worlds.contains_key(HOST_WORLD));
        assert!(!host_contract_version().is_empty());
    }

    #[test]
    fn garbage_is_undecodable() {
        let err = verify_component(b"not wasm").unwrap_err();
        assert!(matches!(err, ContractError::Undecodable(_)), "{err}");
    }

    #[test]
    fn wit_package_is_not_a_component() {
        let err = verify_component(HOST_CONTRACT_WASM).unwrap_err();
        assert_eq!(err, ContractError::NotAComponent);
    }

    #[test]
    fn rendering_is_structural_and_resolves_aliases() {
        let mut resolve = Resolve::default();
        resolve
            .push_str(
                "a.wit",
                "package t:t;
                 interface i {
                   type id = string;
                   record r { a: id, b: option<list<u8>> }
                   resource res;
                   f: func(x: r, h: borrow<res>) -> result<_, string>;
                 }",
            )
            .unwrap();
        let iface = resolve.interfaces.iter().next().unwrap().1;
        let rendered = render_function(&resolve, &iface.functions["f"]);
        assert_eq!(
            rendered,
            "func(x: record { a: string, b: option<list<u8>>, }, h: borrow<resource t:t/i.res>) \
             -> result<_, string>"
        );
    }
}
