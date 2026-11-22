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
//! - the package version must be one this host serves: the host's own
//!   version, or an older one on the same compatibility line (same
//!   `0.x` minor before 1.0, same major after). The `contract_baseline`
//!   test in `oxidhome-wit` guarantees such bumps are additive, and the
//!   per-function comparison below still has to pass;
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
//! type information can't be decoded, and one that both imports and
//! exports the same interface (the decoder would merge the two sides). Comparison is structural: type
//! *names* and doc comments don't matter, the canonical-ABI shape does.
//! Wasmtime's own instantiation type-check would catch most of these
//! too, but later, with an error that names a linker slot rather than
//! the contract version the plugin was built against.

use std::collections::HashSet;
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
    #[error(
        "the component both imports and exports `{interface}`; the decoded types of one side \
         would hide the other's, so the component can't be verified"
    )]
    ImportedAndExported { interface: String },
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

    // The decoder merges same-named interfaces, so an interface that is
    // both imported and exported would only be checked once. No
    // `oxidhome:plugin` world does that; refuse it outright.
    let imported: HashSet<InterfaceId> = world
        .imports
        .values()
        .filter_map(|item| match item {
            WorldItem::Interface { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    for item in world.exports.values() {
        if let WorldItem::Interface { id, .. } = item
            && imported.contains(id)
        {
            return Err(ContractError::ImportedAndExported {
                interface: guest
                    .id_of(*id)
                    .unwrap_or_else(|| "<anonymous interface>".to_owned()),
            });
        }
    }

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
        if !version_served(
            guest.packages[pkg].name.version.as_ref(),
            host.resolve.packages[host.package].name.version.as_ref(),
        ) {
            return Err(ContractError::VersionMismatch {
                plugin: version_string(&guest, pkg),
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
    if Structural::new(guest, host).functions(actual, expected) {
        Ok(())
    } else {
        Err(ContractError::SignatureMismatch {
            item: item.to_owned(),
            plugin: render_function(guest, actual),
            host: render_function(host, expected),
        })
    }
}

/// Structural equality of guest and host types.
///
/// Type definitions can be shared (a tuple of the same tuple of the
/// same tuple...), so a naive walk is exponential in the nesting depth
/// of a hostile component. Pairs already proven equal are memoized, so
/// every (guest type, host type) pair is compared at most once.
struct Structural<'a> {
    guest: &'a Resolve,
    host: &'a Resolve,
    proven: HashSet<(TypeId, TypeId)>,
}

impl<'a> Structural<'a> {
    fn new(guest: &'a Resolve, host: &'a Resolve) -> Self {
        Self {
            guest,
            host,
            proven: HashSet::new(),
        }
    }

    fn functions(&mut self, g: &Function, h: &Function) -> bool {
        is_async(&g.kind) == is_async(&h.kind)
            && g.params.len() == h.params.len()
            && g.params
                .iter()
                .zip(&h.params)
                .all(|(gp, hp)| gp.name == hp.name && self.types(gp.ty, hp.ty))
            && self.opt(g.result, h.result)
    }

    fn opt(&mut self, g: Option<Type>, h: Option<Type>) -> bool {
        match (g, h) {
            (Some(g), Some(h)) => self.types(g, h),
            (None, None) => true,
            _ => false,
        }
    }

    fn types(&mut self, g: Type, h: Type) -> bool {
        let (g, h) = (dealias(self.guest, g), dealias(self.host, h));
        match (g, h) {
            (Type::Id(g), Type::Id(h)) => {
                if self.proven.contains(&(g, h)) {
                    return true;
                }
                let equal = self.defs(g, h);
                if equal {
                    self.proven.insert((g, h));
                }
                equal
            }
            (Type::Id(_), _) | (_, Type::Id(_)) => false,
            (g, h) => g == h,
        }
    }

    fn defs(&mut self, g: TypeId, h: TypeId) -> bool {
        let (gk, hk) = (&self.guest.types[g].kind, &self.host.types[h].kind);
        match (gk, hk) {
            (TypeDefKind::Record(a), TypeDefKind::Record(b)) => {
                a.fields.len() == b.fields.len()
                    && a.fields
                        .iter()
                        .zip(&b.fields)
                        .all(|(x, y)| x.name == y.name && self.types(x.ty, y.ty))
            }
            (TypeDefKind::Variant(a), TypeDefKind::Variant(b)) => {
                a.cases.len() == b.cases.len()
                    && a.cases
                        .iter()
                        .zip(&b.cases)
                        .all(|(x, y)| x.name == y.name && self.opt(x.ty, y.ty))
            }
            (TypeDefKind::Enum(a), TypeDefKind::Enum(b)) => a
                .cases
                .iter()
                .map(|c| &c.name)
                .eq(b.cases.iter().map(|c| &c.name)),
            (TypeDefKind::Flags(a), TypeDefKind::Flags(b)) => a
                .flags
                .iter()
                .map(|f| &f.name)
                .eq(b.flags.iter().map(|f| &f.name)),
            (TypeDefKind::Tuple(a), TypeDefKind::Tuple(b)) => {
                a.types.len() == b.types.len()
                    && a.types
                        .iter()
                        .zip(&b.types)
                        .all(|(x, y)| self.types(*x, *y))
            }
            (TypeDefKind::Option(a), TypeDefKind::Option(b))
            | (TypeDefKind::List(a), TypeDefKind::List(b)) => self.types(*a, *b),
            (TypeDefKind::Result(a), TypeDefKind::Result(b)) => {
                self.opt(a.ok, b.ok) && self.opt(a.err, b.err)
            }
            (TypeDefKind::Map(ak, av), TypeDefKind::Map(bk, bv)) => {
                self.types(*ak, *bk) && self.types(*av, *bv)
            }
            (TypeDefKind::FixedLengthList(a, a_len), TypeDefKind::FixedLengthList(b, b_len)) => {
                a_len == b_len && self.types(*a, *b)
            }
            (TypeDefKind::Future(a), TypeDefKind::Future(b))
            | (TypeDefKind::Stream(a), TypeDefKind::Stream(b)) => self.opt(*a, *b),
            (TypeDefKind::Resource, TypeDefKind::Resource) => {
                resource_name(self.guest, g) == resource_name(self.host, h)
            }
            (TypeDefKind::Handle(Handle::Own(a)), TypeDefKind::Handle(Handle::Own(b)))
            | (TypeDefKind::Handle(Handle::Borrow(a)), TypeDefKind::Handle(Handle::Borrow(b))) => {
                resource_name(self.guest, *a) == resource_name(self.host, *b)
            }
            _ => false,
        }
    }
}

/// Follow `type x = y` aliases to the underlying type.
fn dealias(resolve: &Resolve, mut ty: Type) -> Type {
    while let Type::Id(id) = ty {
        match resolve.types[id].kind {
            TypeDefKind::Type(next) => ty = next,
            _ => break,
        }
    }
    ty
}

fn is_async(kind: &FunctionKind) -> bool {
    matches!(
        kind,
        FunctionKind::AsyncFreestanding
            | FunctionKind::AsyncMethod(_)
            | FunctionKind::AsyncStatic(_)
    )
}

/// Whether a host implementing contract `host` serves a plugin built
/// against `plugin`: same version, or an older one the host's version
/// is a compatible bump of. A newer plugin may call functions this host
/// lacks, so it's refused even on the same line.
fn version_served(plugin: Option<&semver::Version>, host: Option<&semver::Version>) -> bool {
    match (plugin, host) {
        (Some(plugin), Some(host)) => {
            let same_line = if host.major == 0 {
                plugin.major == 0 && plugin.minor == host.minor
            } else {
                plugin.major == host.major
            };
            same_line && plugin <= host
        }
        (None, None) => true,
        _ => false,
    }
}

fn version_string(resolve: &Resolve, pkg: PackageId) -> String {
    resolve.packages[pkg]
        .name
        .version
        .as_ref()
        .map_or_else(|| "(unversioned)".to_owned(), ToString::to_string)
}

/// Longest signature rendered into an error. Rendering expands shared
/// type definitions, so it stops here rather than grow with a hostile
/// component's nesting depth.
const RENDER_LIMIT: usize = 2048;

/// Structural rendering of a function signature, for diagnostics only
/// (equality is [`Structural`]). Truncated at [`RENDER_LIMIT`].
fn render_function(resolve: &Resolve, func: &Function) -> String {
    let mut out = String::new();
    if is_async(&func.kind) {
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
    if out.len() > RENDER_LIMIT {
        let mut end = RENDER_LIMIT;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str(" …");
    }
    out
}

fn render_type(resolve: &Resolve, ty: Type, out: &mut String) {
    if out.len() > RENDER_LIMIT {
        return;
    }
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

/// Resources are nominal: identify one by its defining interface and
/// name, following `type x = y` aliases to the definition. The package
/// version is left out; [`version_served`] already vetted it, and an
/// older plugin's `media@0.1.0.pipe-writer` is the host's
/// `media@0.1.1.pipe-writer`.
fn resource_name(resolve: &Resolve, mut id: TypeId) -> String {
    while let TypeDefKind::Type(Type::Id(next)) = resolve.types[id].kind {
        id = next;
    }
    let def = &resolve.types[id];
    let mut out = String::new();
    match def.owner {
        TypeOwner::Interface(iface) => {
            let iface = &resolve.interfaces[iface];
            if let Some(pkg) = iface.package {
                let name = &resolve.packages[pkg].name;
                let _ = write!(out, "{}:{}/", name.namespace, name.name);
            }
            out.push_str(iface.name.as_deref().unwrap_or("<anonymous>"));
            out.push('.');
        }
        TypeOwner::World(world) => {
            out.push_str(&resolve.worlds[world].name);
            out.push('.');
        }
        TypeOwner::None => {}
    }
    out.push_str(def.name.as_deref().unwrap_or("<anonymous>"));
    out
}

fn render_resource(resolve: &Resolve, id: TypeId, out: &mut String) {
    out.push_str("resource ");
    out.push_str(&resource_name(resolve, id));
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
        assert_ne!(host_contract_version(), "");
    }

    #[test]
    fn served_versions_follow_the_compatibility_line() {
        let v = |s: &str| s.parse::<semver::Version>().unwrap();
        let served = |p: &str, h: &str| version_served(Some(&v(p)), Some(&v(h)));
        assert!(served("0.1.0", "0.1.0"));
        assert!(served("0.1.0", "0.1.3"));
        assert!(!served("0.1.4", "0.1.3"), "newer plugin");
        assert!(!served("0.1.0", "0.2.0"), "breaking 0.x bump");
        assert!(served("1.0.0", "1.4.0"));
        assert!(!served("1.5.0", "1.4.0"), "newer plugin");
        assert!(!served("1.4.0", "2.0.0"), "breaking major bump");
        assert!(!served("0.9.0", "1.0.0"));
        assert!(version_served(None, None));
        assert!(!version_served(None, Some(&v("0.1.0"))));
        assert!(!version_served(Some(&v("0.1.0")), None));
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

    /// Shared nested definitions must not blow up comparison or
    /// diagnostics: 40 levels of `tuple<t, t>` expand to 2^40 leaves.
    #[test]
    fn deeply_shared_types_compare_in_bounded_time_and_space() {
        let nested = |leaf: &str| {
            let mut wit =
                format!("package t:t;\ninterface i {{\n type t0 = tuple<{leaf}, {leaf}>;\n");
            for n in 1..=40 {
                let _ = writeln!(wit, " type t{n} = tuple<t{m}, t{m}>;", m = n - 1);
            }
            wit.push_str(" f: func(x: t40);\n}\n");
            let mut resolve = Resolve::default();
            resolve.push_str("n.wit", &wit).unwrap();
            resolve
        };
        let (guest, host, same) = (nested("u8"), nested("u16"), nested("u8"));
        let func = |r: &Resolve| r.interfaces.iter().next().unwrap().1.functions["f"].clone();

        compare_functions(&guest, &func(&guest), &same, &func(&same), "f").expect("equal");
        let err = compare_functions(&guest, &func(&guest), &host, &func(&host), "f").unwrap_err();
        let ContractError::SignatureMismatch { plugin, host, .. } = err else {
            panic!("expected SignatureMismatch, got {err}");
        };
        assert!(plugin.len() <= RENDER_LIMIT + 4, "{}", plugin.len());
        assert!(host.ends_with(" …"));
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
