#!/usr/bin/env python3
"""Drop-in-replaceability gate for tachyon-web against axum (+ axum-core).

Two subcommands, both driven by rustdoc JSON so nothing here is a hand-curated
list of "the parity surface":

    python3 scripts/api_diff.py parity     # default; the compatibility gate
    python3 scripts/api_diff.py docs       # public-API doc-footer lint (--fix to apply)

WHAT "DROP-IN" MEANS HERE
-------------------------
The gate asks one question: can a project delete `use axum::...` / `axum = "0.8"`,
write `tachyon_web` instead, and still compile? That is stricter than "the same
names exist somewhere", which is all the previous version of this script checked.
Concretely, `parity` requires all of:

  1. PATH      every public path axum exposes is reachable at the *same* path in
               tachyon-web (`axum::handler::Handler` -> `tachyon_web::handler::Handler`).
               Name-only matching is useless here: `use` statements name paths.
  2. KIND/SIG  the item at that path is the same kind with the same rendered
               signature (generics, bounds, where-clauses, defaults, fn headers).
  3. MEMBERS   struct fields, enum variants (with payloads), trait items, and
               *public inherent methods* all exist with matching signatures.
               This is where the real surface lives -- `Router::route`,
               `MethodRouter::merge`, `Redirect::permanent` are members, not
               top-level items, and a check that skips them proves almost nothing.
  4. IMPLS     every non-blanket, non-synthetic trait impl axum provides on a type
               is also provided by tachyon-web (`impl Service for Router`,
               `impl IntoResponse for X`, `Clone`, `Default`, ...).
  5. FEATURES  every axum Cargo feature name also exists in tachyon-web, and the
               default feature set matches -- `axum = { features = ["ws"] }` has to
               keep working after the swap.
  6. DEPS      shared public dependencies (http, hyper, bytes, tower, serde, ...)
               resolve to the same major version on both sides. If they don't, the
               re-exported types are simply different types and nothing else matters.

Anything tachyon-web has *in addition* is reported as an extension and never fails
the gate: parity is a superset relation, not equality.

Known limits (be honest about what a green run does NOT prove):
  - Behaviour is not checked, only shape. Same signature, different semantics passes.
  - Blanket and auto-trait impls are skipped (they are noise from third-party
    crates and are re-derived by the compiler anyway).
  - `macro_rules!`/proc-macro bodies are compared by presence only.
  - Only the feature set in TACHYON_FEATURES / AXUM_FEATURES is documented and
    diffed; a feature combination outside that is not covered.
  - Rustdoc JSON item ids are file-local. Never merge two files' `index`/`paths`
    tables; each file stays its own `Crate` and results are merged after walking.

USAGE
-----
    python3 scripts/api_diff.py                      # build both sides, run the gate
    python3 scripts/api_diff.py parity --cache DIR   # reuse/keep built rustdoc JSON
    python3 scripts/api_diff.py parity --show-extensions
    python3 scripts/api_diff.py parity --json report.json
    python3 scripts/api_diff.py docs --check         # CI: doc footers correct?
    python3 scripts/api_diff.py docs --fix           # rewrite footers in src/

Accepted, deliberate deviations go in scripts/api_parity_allow.txt (one
`CODE<TAB>path` per line, `#` comments) so they are reviewed in a diff rather
than argued about in CI logs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOW_FILE = REPO_ROOT / "scripts" / "api_parity_allow.txt"

# Every tachyon-web feature except `tor`/`i2p` (vendored C++ toolchains, no bearing
# on public API shape) and `fips` (a build-mode modifier, not additive surface).
# Kept in sync with the CI "full (no tor/i2p)" matrix entry.
TACHYON_FEATURES = (
    "json,cookies,matched-path,original-uri,http1,http2,tower-log,ws,form,query,"
    "sse,tls,cert-gen,lets-encrypt,http3,compression-full,multipart"
)

# Every non-private axum 0.8 feature, so nothing feature-gated is invisible here.
AXUM_FEATURES = (
    "form,http1,http2,json,macros,multipart,query,tokio,tracing,ws,"
    "matched-path,original-uri,tower-log"
)

# Public dependencies whose types cross the API boundary in both crates. A major
# version split here makes drop-in replacement impossible regardless of shape.
SHARED_PUBLIC_DEPS = (
    "http", "http-body", "http-body-util", "hyper", "bytes",
    "tower", "tower-service", "tower-layer", "serde", "serde_json", "futures-core",
)

# Doc footers. Exactly one line, exact text -- the linter regenerates them, so the
# format cannot drift. The axum path is a plain code span, not an intra-doc link:
# `axum` is not a dependency, so a link would fail `broken_intra_doc_links` under
# the `-D warnings` rustdoc job.
PARITY_FOOTER = "*Axum compatibility: drop-in replacement for `{axum_path}`.*"
EXTENSION_FOOTER = "*Tachyon extension: no `axum` equivalent.*"
FOOTER_RE = re.compile(r"^\s*///\s*\*(?:Axum compatibility|Tachyon extension):.*\*\s*$")

LEAF_KINDS = {
    "function", "struct", "enum", "trait", "type_alias",
    "macro", "proc_macro", "constant", "static", "union", "trait_alias",
}

# Finding codes that fail the gate. EXTENSION and NODOC are informational.
FATAL_CODES = {
    "PATH", "KIND", "SIGNATURE", "MEMBER", "MEMBER_SIGNATURE",
    "IMPL", "FEATURE", "DEFAULT_FEATURES", "DEP_VERSION",
}


# ---------------------------------------------------------------------------
# Building rustdoc JSON
# ---------------------------------------------------------------------------

def load(path):
    with open(path) as f:
        return json.load(f)


def run(cmd, cwd=None, env=None):
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def rustdoc_env():
    env = dict(os.environ)
    env["RUSTDOCFLAGS"] = "--cap-lints=warn"
    return env


def lock_versions(lock_path: Path) -> dict[str, str]:
    """name -> version for every package in a Cargo.lock."""
    out = {}
    text = lock_path.read_text()
    for block in text.split("[[package]]"):
        n = re.search(r'^name = "([^"]+)"', block, re.M)
        v = re.search(r'^version = "([^"]+)"', block, re.M)
        if n and v:
            out[n.group(1)] = v.group(1)
    return out


def build_tachyon_json(cache: Path | None, force: bool = False) -> Path:
    out = REPO_ROOT / "target" / "doc" / "tachyon_web.json"
    if not force and cache and (cache / "tachyon_web.json").exists():
        return cache / "tachyon_web.json"
    run(
        ["cargo", "+nightly", "rustdoc", "--lib", "-p", "tachyon-web",
         "--no-default-features", "--features", TACHYON_FEATURES,
         "--", "-Z", "unstable-options", "--output-format", "json"],
        cwd=REPO_ROOT, env=rustdoc_env(),
    )
    if not out.exists():
        raise RuntimeError(f"expected rustdoc output at {out}, not found")
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "tachyon_web.json").write_bytes(out.read_bytes())
        return cache / "tachyon_web.json"
    return out


def build_axum_json(axum_version: str, work: Path) -> tuple[Path, Path, Path]:
    """Documents axum and axum-core from a throwaway probe crate pinned to the exact
    version this repo's Cargo.lock resolves. axum-core's items (FromRequest,
    IntoResponse, FromRef, ...) are re-exported by axum but not inlined into axum's
    own JSON, so both crates are documented and unioned. Returns (axum, axum_core,
    probe Cargo.lock)."""
    probe = work / "axum-probe"
    feats = ", ".join(f'"{f}"' for f in AXUM_FEATURES.split(","))
    (probe / "src").mkdir(parents=True, exist_ok=True)
    (probe / "Cargo.toml").write_text(
        f'[package]\nname = "axum-probe"\nversion = "0.0.0"\nedition = "2021"\n'
        f'publish = false\n\n[dependencies]\n'
        f'axum = {{ version = "={axum_version}", features = [{feats}] }}\n'
        f'tokio = {{ version = "1", features = ["full"] }}\n\n[workspace]\n'
    )
    (probe / "src" / "main.rs").write_text("fn main() {}\n")

    doc = probe / "target" / "doc"
    if not (doc / "axum.json").exists() or not (doc / "axum_core.json").exists():
        for crate_name in ("axum", "axum-core"):
            run(["cargo", "+nightly", "rustdoc", "-p", crate_name, "--lib",
                 "--", "-Z", "unstable-options", "--output-format", "json"],
                cwd=probe, env=rustdoc_env())
    for p in (doc / "axum.json", doc / "axum_core.json"):
        if not p.exists():
            raise RuntimeError(f"expected rustdoc output at {p}, not found")
    return doc / "axum.json", doc / "axum_core.json", probe / "Cargo.lock"


# ---------------------------------------------------------------------------
# Crate wrapper
# ---------------------------------------------------------------------------

class Crate:
    """One rustdoc JSON document. Item ids are only meaningful inside a single
    file, so two crates must never share index/paths tables."""

    def __init__(self, data, label, own_crates=()):
        self.data = data
        self.label = label
        self.index = data["index"]
        self.paths = data["paths"]
        self.crate_id = self.index[str(data["root"])]["crate_id"]
        # Crates whose items count as "ours" when canonicalising type paths. axum
        # and axum-core are one API surface as far as a downstream user is
        # concerned, so an axum-core trait must render the same on both sides.
        self.own_crates = set(own_crates) | {self.index[str(data["root"])]["name"]}

    def item(self, iid):
        return self.index.get(str(iid))


# ---------------------------------------------------------------------------
# Structural rendering
#
# Types are canonicalised so the two crates are comparable: an item defined in
# the crate being rendered becomes `Self::<Leaf>` (its module path is checked
# separately, by the PATH rule, and would otherwise be double-reported), while a
# foreign item keeps its full path so `http::StatusCode` can never silently
# compare equal to a same-named local type.
# ---------------------------------------------------------------------------

# The name of the type/trait whose members are currently being rendered (set by
# `describe`/`impl_members` for the duration of one item's render). When a same-crate
# type reference resolves to exactly this name, it means the source spelled out the
# enclosing type's own name (`-> Message`) where another equally-valid spelling would
# have used the `Self` keyword (`-> Self`) -- both compile to the identical type and a
# caller can never tell which one the source used, so this collapses both spellings to
# bare `Self` rather than reporting a difference that isn't real.
_CURRENT_SELF_NAME: str | None = None


def type_path(c: Crate, iid) -> str:
    p = c.paths.get(str(iid))
    if p:
        if p["path"][0] in c.own_crates:
            leaf = p["path"][-1]
            return "Self" if leaf == _CURRENT_SELF_NAME else "Self::" + leaf
        return "::".join(p["path"])
    it = c.item(iid)
    if it and it.get("name"):
        name = it["name"]
        return "Self" if name == _CURRENT_SELF_NAME else "Self::" + name
    return f"#{iid}"


# Canonicalizes generic type/const parameter names the same way `_CURRENT_SELF_NAME`
# canonicalizes `Self`: `fn get_service<Svc>(Svc)` and `fn get_service<T>(T)` are the
# exact same signature to every caller (nobody can turbofish a type by its declared
# name), so a param named `Svc` on one side and `T` on the other must not be reported
# as a real difference. Pushed by `render_generics` for the duration of whatever
# declares those params (a function, or a struct/enum/trait's own header); popped by
# the same caller once every downstream render (params, return type, fields, ...) that
# could reference them is done.
_GENERIC_MAP: dict[str, str] = {}
_GENERIC_COUNTER = [0]


def push_generic_scope(names) -> list[tuple[str, str | None]]:
    undo = []
    for name in names:
        undo.append((name, _GENERIC_MAP.get(name)))
        _GENERIC_MAP[name] = f"T{_GENERIC_COUNTER[0]}"
        _GENERIC_COUNTER[0] += 1
    return undo


def pop_generic_scope(undo) -> None:
    for name, old in reversed(undo):
        if old is None:
            _GENERIC_MAP.pop(name, None)
        else:
            _GENERIC_MAP[name] = old


def render_type(c: Crate, t) -> str:
    if t is None:
        return "()"
    if "generic" in t:
        return _GENERIC_MAP.get(t["generic"], t["generic"])
    if "primitive" in t:
        return t["primitive"]
    if "tuple" in t:
        return "(" + ", ".join(render_type(c, x) for x in t["tuple"]) + ")"
    if "slice" in t:
        return "[" + render_type(c, t["slice"]) + "]"
    if "array" in t:
        return f'[{render_type(c, t["array"]["type"])}; {t["array"]["len"]}]'
    if "raw_pointer" in t:
        rp = t["raw_pointer"]
        return ("*mut " if rp["is_mutable"] else "*const ") + render_type(c, rp["type"])
    if "borrowed_ref" in t:
        br = t["borrowed_ref"]
        lt = (br.get("lifetime") + " ") if br.get("lifetime") else ""
        mut = "mut " if br.get("is_mutable") else ""
        return f"&{lt}{mut}{render_type(c, br['type'])}"
    if "resolved_path" in t:
        rp = t["resolved_path"]
        path = type_path(c, rp["id"])
        # Bare `Self` already carries whatever generic args the enclosing impl has --
        # `Self<H, T, S>` isn't valid Rust, so don't append the resolved args when the
        # reference collapsed to literal `Self` (see `_CURRENT_SELF_NAME`).
        if path == "Self":
            return path
        return path + render_generic_args(c, rp.get("args"))
    if "qualified_path" in t:
        qp = t["qualified_path"]
        base = render_type(c, qp["self_type"])
        trait = qp.get("trait")
        tname = type_path(c, trait["id"]) if trait else ""
        return f"<{base} as {tname}>::{qp['name']}"
    if "impl_trait" in t:
        return "impl " + " + ".join(render_bound(c, b) for b in t["impl_trait"])
    if "dyn_trait" in t:
        dt = t["dyn_trait"]
        parts = [type_path(c, tr["trait"]["id"]) + render_generic_args(c, tr["trait"].get("args"))
                 for tr in dt.get("traits", [])]
        if dt.get("lifetime"):
            parts.append(dt["lifetime"])
        return "dyn " + " + ".join(parts)
    if "function_pointer" in t:
        fp = t["function_pointer"]
        sig = fp.get("sig", {})
        ins = ", ".join(render_type(c, ty) for _, ty in sig.get("inputs", []))
        out = render_type(c, sig["output"]) if sig.get("output") else "()"
        return f"fn({ins}) -> {out}"
    if "infer" in t:
        return "_"
    return json.dumps(t, sort_keys=True)[:120]


def render_generic_args(c: Crate, args) -> str:
    if not args:
        return ""
    if "angle_bracketed" in args:
        parts = []
        for a in args["angle_bracketed"].get("args", []):
            if "type" in a:
                parts.append(render_type(c, a["type"]))
            elif "lifetime" in a:
                parts.append(a["lifetime"])
            elif "const" in a:
                parts.append(str(a["const"].get("expr", "const")))
        for b in args["angle_bracketed"].get("constraints", []):
            parts.append(f"{b.get('name')}=..")
        return "<" + ", ".join(parts) + ">" if parts else ""
    if "parenthesized" in args:
        p = args["parenthesized"]
        ins = ", ".join(render_type(c, x) for x in p.get("inputs", []))
        out = render_type(c, p["output"]) if p.get("output") else ""
        return f"({ins}) -> {out}" if out else f"({ins})"
    return ""


def render_bound(c: Crate, b) -> str:
    if "trait_bound" in b:
        tb = b["trait_bound"]
        hrtb = tb.get("generic_params") or []
        lead = "for<" + ", ".join(p["name"] for p in hrtb) + "> " if hrtb else ""
        modifier = tb.get("modifier") or ""
        prefix = "?" if modifier == "maybe" else ""
        trait_path = type_path(c, tb["trait"]["id"])
        args = "" if trait_path == "Self" else render_generic_args(c, tb["trait"].get("args"))
        return lead + prefix + trait_path + args
    if "outlives" in b:
        return b["outlives"]
    if "use" in b:
        return "use<..>"
    return "?"


def render_generics(c: Crate, generics) -> str:
    """Params keep their declared defaults (turbofish-observable); everything else that
    Rust guarantees is call-site-invisible is normalized away:

    - Parameter NAMES aren't rendered here at all (see `render_fn_sig`) -- Rust has no
      named-argument calls, so `<T>` vs `<S>` or `fn(x: T)` vs `fn(y: T)` can never be
      distinguished by a caller.
    - A bound spelled inline (`<T: Bound>`) and the identical bound spelled as a
      trailing `where T: Bound` compile to the exact same item and are otherwise
      indistinguishable, so both are merged into one sorted `where` list here rather
      than rendered differently depending on which style the source happened to use.
    """
    where = set()
    parts = []
    for p in generics.get("params", []):
        kind = p["kind"]
        # Looks up the canonical name a caller's `push_generic_scope` assigned this
        # param (see `_GENERIC_MAP`), falling back to the declared name for scopes
        # nobody pushed (lifetimes are left as-is; they're rarely the source of a
        # false mismatch and canonicalizing them would collide with the `'` syntax).
        name = _GENERIC_MAP.get(p["name"], p["name"])
        if "type" in kind:
            k = kind["type"]
            if k.get("is_synthetic"):
                continue
            for b in k.get("bounds", []):
                where.add(f"{name}: {render_bound(c, b)}")
            s = name
            if k.get("default"):
                s += " = " + render_type(c, k["default"])
            parts.append(s)
        elif "lifetime" in kind:
            outlives = kind["lifetime"].get("outlives") or []
            parts.append(p["name"] + (": " + " + ".join(outlives) if outlives else ""))
        elif "const" in kind:
            k = kind["const"]
            s = f'{name}: {render_type(c, k["type"])}'
            if k.get("default"):
                s += " = " + str(k["default"])
            parts.append(s)
    for w in generics.get("where_predicates", []):
        if "bound_predicate" in w:
            bp = w["bound_predicate"]
            for b in bp["bounds"]:
                where.add(f"{render_type(c, bp['type'])}: {render_bound(c, b)}")
        elif "lifetime_predicate" in w:
            lp = w["lifetime_predicate"]
            where.add(f"{lp['lifetime']}: {' + '.join(lp.get('outlives', []))}")
        elif "eq_predicate" in w:
            eq = w["eq_predicate"]
            where.add(f"{render_type(c, eq['lhs'])} == ..")
    s = "<" + ", ".join(parts) + ">" if parts else ""
    if where:
        s += " where " + ", ".join(sorted(where))
    return s


def render_fn_sig(c: Crate, item) -> str:
    inner = item["inner"]["function"]
    sig, header = inner["sig"], inner["header"]
    # Reset so the Nth declared type param always canonicalizes to the same `TN` on
    # both sides of a comparison, regardless of how many OTHER items were rendered
    # earlier in this run (a global monotonic counter would make the assigned name
    # depend on render order, which differs between the two crates and would turn
    # this into a new source of false mismatches instead of removing one).
    _GENERIC_COUNTER[0] = 0
    quals = ""
    if header.get("is_const"):
        quals += "const "
    if header.get("is_async"):
        quals += "async "
    if header.get("is_unsafe"):
        quals += "unsafe "
    abi = header.get("abi")
    if isinstance(abi, str) and abi != "Rust":
        quals += f'extern "{abi}" '
    # Parameter names are dropped: Rust has no named-argument calls, so `fn(x: T)` and
    # `fn(y: T)` (including `self` vs `&self` vs `&mut self`, whose distinction survives
    # here through the *type* -- `Self` vs `&Self` vs `&mut Self` -- not the name) are
    # 100% call-compatible and must not be reported as a signature difference.
    #
    # The function's own type/const generic param names are canonicalized too (see
    # `_GENERIC_MAP`): `fn get_service<Svc>(Svc)` and `fn get_service<T>(T)` are the
    # same signature to every caller, since nobody can turbofish a type by its
    # declared name -- only its position.
    own_params = [
        p["name"]
        for p in inner["generics"].get("params", [])
        if ("type" in p["kind"] and not p["kind"]["type"].get("is_synthetic"))
        or "const" in p["kind"]
    ]
    undo = push_generic_scope(own_params)
    try:
        generics = render_generics(c, inner["generics"])
        ins = ", ".join(render_type(c, ty) for _, ty in sig["inputs"])
        out = render_type(c, sig["output"]) if sig.get("output") else "()"
    finally:
        pop_generic_scope(undo)
    dots = ", ..." if sig.get("is_c_variadic") else ""
    return f"{quals}fn{generics}({ins}{dots}) -> {out}"


def field_members(c: Crate, kind) -> dict[str, str]:
    """Public fields of a struct/variant, keyed by name (tuple fields by index)."""
    out = {}
    if "plain" in kind:
        for fid in kind["plain"].get("fields", []):
            f = c.item(fid)
            if f and "struct_field" in f.get("inner", {}):
                out[f["name"]] = render_type(c, f["inner"]["struct_field"])
        if kind["plain"].get("has_stripped_fields"):
            out["<private fields>"] = "present"
    elif "tuple" in kind:
        for i, fid in enumerate(kind["tuple"]):
            if fid is None:
                out[f".{i}"] = "<private>"
                continue
            f = c.item(fid)
            if f and "struct_field" in f.get("inner", {}):
                out[f".{i}"] = render_type(c, f["inner"]["struct_field"])
    elif "unit" in kind:
        pass
    return out


# ---------------------------------------------------------------------------
# Members: fields, variants, trait items, public inherent methods.
# ---------------------------------------------------------------------------

def impl_members(c: Crate, impl_ids) -> tuple[dict[str, str], set[str]]:
    """Returns (public inherent methods/consts, rendered trait impls).

    Blanket and synthetic (auto-trait) impls are skipped: they come from
    third-party generic impls and from the compiler, are re-derived identically
    on both sides, and would otherwise bury real findings in noise.
    """
    methods: dict[str, str] = {}
    traits: set[str] = set()
    for iid in impl_ids or ():
        it = c.item(iid)
        if not it or "impl" not in it.get("inner", {}):
            continue
        i = it["inner"]["impl"]
        if i.get("is_synthetic") or i.get("blanket_impl"):
            continue
        trait = i.get("trait")
        if trait:
            neg = "!" if i.get("is_negative") else ""
            unsafe = "unsafe " if i.get("is_unsafe") else ""
            traits.add(f"{unsafe}impl {neg}{type_path(c, trait['id'])}"
                       f"{render_generic_args(c, trait.get('args'))} for "
                       f"{render_type(c, i['for'])}")
            continue
        for mid in i.get("items", []):
            m = c.item(mid)
            if not m or m.get("visibility") != "public":
                continue
            mk = next(iter(m.get("inner", {})), None)
            if mk == "function":
                methods[f"fn {m['name']}"] = render_fn_sig(c, m)
            elif mk == "assoc_const":
                methods[f"const {m['name']}"] = render_type(c, m["inner"]["assoc_const"].get("type"))
            elif mk == "assoc_type":
                methods[f"type {m['name']}"] = "assoc type"
    return methods, traits


def describe(c: Crate, item) -> tuple[str, dict[str, str], set[str]]:
    """(signature, members, trait impls) for one item."""
    inner_all = item.get("inner", {})
    if not inner_all:
        return "?", {}, set()
    k = next(iter(inner_all))
    inner = inner_all[k]
    name = item.get("name") or "?"
    members: dict[str, str] = {}
    traits: set[str] = set()
    global _CURRENT_SELF_NAME
    prev_self_name = _CURRENT_SELF_NAME
    _CURRENT_SELF_NAME = name if k in ("struct", "union", "enum", "trait", "trait_alias") else None
    try:
        if k == "function":
            return render_fn_sig(c, item), members, traits
        if k == "trait":
            for mid in inner.get("items", []):
                m = c.item(mid)
                if not m:
                    continue
                mk = next(iter(m.get("inner", {})), None)
                if mk == "function":
                    members[f"fn {m['name']}"] = render_fn_sig(c, m)
                elif mk == "assoc_type":
                    at = m["inner"]["assoc_type"]
                    bs = " + ".join(render_bound(c, b) for b in at.get("bounds", []))
                    members[f"type {m['name']}"] = bs or "-"
                elif mk == "assoc_const":
                    members[f"const {m['name']}"] = render_type(c, m["inner"]["assoc_const"].get("type"))
            sup = " + ".join(sorted(render_bound(c, b) for b in inner.get("bounds", [])))
            head = ("unsafe " if inner.get("is_unsafe") else "") + "trait"
            sig = f"{head}{render_generics(c, inner.get('generics', {}))}" + (f": {sup}" if sup else "")
            return sig, members, traits
        if k == "trait_alias":
            bs = " + ".join(render_bound(c, b) for b in inner.get("bounds", []))
            return f"trait_alias{render_generics(c, inner.get('generics', {}))} = {bs}", members, traits
        if k in ("struct", "union"):
            skind = inner.get("kind", {}) if k == "struct" else {"plain": {
                "fields": inner.get("fields", []), "has_stripped_fields": inner.get("has_stripped_fields")}}
            shape = next(iter(skind), "?")
            members = field_members(c, skind)
            m2, traits = impl_members(c, inner.get("impls"))
            members.update(m2)
            return f"{k}{render_generics(c, inner.get('generics', {}))} ({shape})", members, traits
        if k == "enum":
            for vid in inner.get("variants", []):
                v = c.item(vid)
                if not v:
                    continue
                vk = v["inner"]["variant"]
                shape = vk.get("kind", {})
                if isinstance(shape, str):
                    members[f"variant {v['name']}"] = shape
                else:
                    fields = field_members(c, shape)
                    members[f"variant {v['name']}"] = ", ".join(
                        f"{n}: {t}" for n, t in sorted(fields.items())) or next(iter(shape), "unit")
            m2, traits = impl_members(c, inner.get("impls"))
            members.update(m2)
            return f"enum{render_generics(c, inner.get('generics', {}))}", members, traits
        if k == "type_alias":
            return ("type" + render_generics(c, inner.get("generics", {}))
                    + " = " + render_type(c, inner["type"])), members, traits
        if k == "constant":
            return "const: " + render_type(c, inner.get("type")), members, traits
        if k == "static":
            return ("static" + (" mut" if inner.get("is_mutable") else "")
                    + ": " + render_type(c, inner.get("type"))), members, traits
        if k in ("macro", "proc_macro"):
            return f"<{k} {name}, body not compared>", members, traits
    except Exception as e:  # rendering must never take down the whole run
        return f"<render error: {e}>", members, traits
    finally:
        _CURRENT_SELF_NAME = prev_self_name
    return f"<unhandled kind {k}>", members, traits


# ---------------------------------------------------------------------------
# Public surface walk
# ---------------------------------------------------------------------------

def namespace_of(kind: str) -> str:
    if kind in ("function", "constant", "static"):
        return "value"
    if kind in ("macro", "proc_macro"):
        return "macro"
    return "type"


class Entry:
    __slots__ = ("ns", "kind", "sig", "members", "traits", "item_id", "span", "label",
                 "attrs", "docs", "name")

    def __init__(self, ns, kind, sig, members, traits, item_id, span, label, attrs, docs,
                 name=""):
        self.name = name
        self.ns, self.kind, self.sig = ns, kind, sig
        self.members, self.traits = members, traits
        self.item_id, self.span, self.label, self.attrs = item_id, span, label, attrs
        self.docs = docs


def collect_public_api(c: Crate) -> dict[tuple[str, str], Entry]:
    """Walks c's public module tree from the crate root, following `pub use`
    re-exports (named and glob) to the paths items are actually reachable at.
    Key is (namespace, "a::b::Name") -- the path a downstream `use` must name."""
    results: dict[tuple[str, str], Entry] = {}

    def record(path, kind, item, stub=None):
        key = (namespace_of(kind), "::".join(path))
        if key in results and stub is not None:
            return  # never let a stub overwrite a resolved entry
        if stub is not None:
            sig, members, traits = stub, {}, set()
            item_id = span = attrs = docs = None
        else:
            sig, members, traits = describe(c, item)
            item_id, span = item.get("id"), item.get("span")
            attrs, docs = item.get("attrs") or [], item.get("docs")
        results[key] = Entry(key[0], kind, sig, members, traits, item_id, span, c.label,
                             attrs, docs, path[-1])

    def handle_use(use_item, path, seen):
        u = use_item.get("inner", {}).get("use", {})
        name = use_item.get("name") or u.get("name")
        target_id = u.get("id")
        if u.get("is_glob"):
            if target_id is not None:
                tgt = c.item(target_id)
                if tgt is not None and tgt.get("crate_id") == c.crate_id and "module" in tgt.get("inner", {}):
                    walk(target_id, path, seen)
            return
        if target_id is None or not name:
            return
        tgt = c.item(target_id)
        if tgt is not None and tgt.get("crate_id") == c.crate_id:
            tk = next(iter(tgt.get("inner", {})), None)
            if tk == "module":
                walk(target_id, path + (name,), seen)
            elif tk == "use":
                handle_use(tgt, path, seen)
            elif tk in LEAF_KINDS:
                record(path + (name,), tk, tgt)
            return
        # Target lives in another JSON file (axum re-exporting axum-core, or either
        # crate re-exporting `http`/`bytes`). We only have path metadata; record the
        # foreign path as the signature so `axum::body::Bytes` and
        # `tachyon_web::Bytes` compare as "the same re-export of bytes::Bytes".
        p = c.paths.get(str(target_id))
        if not p:
            return
        pkind = p.get("kind", "?")
        if pkind == "module" or pkind not in LEAF_KINDS:
            return
        record(path + (name,), pkind, None, stub=f"re-export of {'::'.join(p['path'])}")

    def walk(module_id, path, seen):
        if module_id in seen:
            return
        seen = seen | {module_id}
        mod = c.item(module_id)
        if mod is None or mod.get("visibility") != "public":
            return
        minner = mod.get("inner", {}).get("module")
        if minner is None:
            return
        for child_id in minner.get("items", []):
            child = c.item(child_id)
            if child is None or child.get("crate_id") != c.crate_id:
                continue
            if child.get("visibility") != "public":
                continue
            ck = next(iter(child.get("inner", {})), None)
            cname = child.get("name")
            if ck == "use":
                handle_use(child, path, seen)
            elif ck == "module" and cname:
                walk(child_id, path + (cname,), seen)
            elif ck in LEAF_KINDS and cname:
                record(path + (cname,), ck, child)

    walk(int(c.data["root"]), (), set())
    return results


AXUM_GROUP = ("axum", "axum_core")


def axum_crates(axum_json, core_json) -> list[Crate]:
    return [Crate(load(axum_json), "axum", AXUM_GROUP),
            Crate(load(core_json), "axum_core", AXUM_GROUP)]


def merge_axum(crates: list[Crate]) -> dict[tuple[str, str], Entry]:
    """Union of axum and axum-core's own walks, keyed by the path *axum* exposes.
    axum-core paths are rewritten onto axum's, since downstream code writes
    `axum::response::IntoResponse`, never `axum_core::...`. A resolved entry
    always wins over the re-export stub axum's own walk produced for it."""
    axum, core = crates[0], crates[1]
    merged = dict(collect_public_api(axum))
    core_api = collect_public_api(core)
    by_name = defaultdict(list)
    for (ns, path), e in core_api.items():
        by_name[(ns, path.split("::")[-1])].append(e)
    for key, e in list(merged.items()):
        if e.sig.startswith("re-export of axum_core::"):
            cands = by_name.get((key[0], key[1].split("::")[-1]))
            if cands and len(cands) == 1:
                merged[key] = cands[0]
    return merged


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, code, path, detail, hint=""):
        self.code, self.path, self.detail, self.hint = code, path, detail, hint

    def key(self):
        return f"{self.code}\t{self.path}"

    def __str__(self):
        s = f"[{self.code}] {self.path}\n    {self.detail}"
        if self.hint:
            s += f"\n    hint: {self.hint}"
        return s


def load_allowlist() -> set[str]:
    if not ALLOW_FILE.exists():
        return set()
    out = set()
    for line in ALLOW_FILE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add("\t".join(part.strip() for part in line.split("\t", 1)))
    return out


def diff_features() -> list[Finding]:
    """axum's Cargo feature names must survive the swap: a project that wrote
    `axum = { features = ["ws"] }` has to be able to write the same for
    tachyon-web, and `default-features = false` has to mean the same thing."""
    findings = []
    tach = REPO_ROOT / "Cargo.toml"
    text = tach.read_text()
    m = re.search(r"^\[features\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    tach_feats = set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", m.group(1), re.M)) if m else set()
    axum_feats = set(AXUM_FEATURES.split(","))
    # axum's default set, from its published manifest (0.8).
    axum_default = {"form", "http1", "json", "matched-path", "original-uri",
                    "query", "tokio", "tower-log", "tracing"}
    for f in sorted(axum_feats - tach_feats):
        findings.append(Finding(
            "FEATURE", f"feature `{f}`",
            "axum exposes this Cargo feature; tachyon-web does not.",
            "add it as a (possibly empty) feature so downstream `features = [...]` keeps resolving"))
    dm = re.search(r"^default\s*=\s*\[(.*?)\]", m.group(1), re.M | re.S) if m else None
    tach_default = set(re.findall(r'"([^"]+)"', dm.group(1))) if dm else set()
    only_axum = (axum_default & tach_feats) - tach_default
    if only_axum:
        findings.append(Finding(
            "DEFAULT_FEATURES", "[features] default",
            f"on by default in axum but not tachyon-web: {', '.join(sorted(only_axum))}",
            "a project that never listed these features gets a smaller API after the swap"))
    return findings


def diff_deps(probe_lock: Path | None) -> list[Finding]:
    """Re-exported types are only interchangeable if both crates resolve the same
    major version of the crate that defines them."""
    if probe_lock is None or not probe_lock.exists():
        return []
    tach = lock_versions(REPO_ROOT / "Cargo.lock")
    axum = lock_versions(probe_lock)

    def major(v):
        parts = v.split(".")
        return parts[0] if parts[0] != "0" else ".".join(parts[:2])

    out = []
    for dep in SHARED_PUBLIC_DEPS:
        tv, av = tach.get(dep), axum.get(dep)
        if tv and av and major(tv) != major(av):
            out.append(Finding(
                "DEP_VERSION", f"dependency `{dep}`",
                f"tachyon-web resolves {tv}, axum resolves {av}",
                "types re-exported from this crate are not the same type across the swap"))
    return out


def sig_compatible(axum_sig: str, tach_sig: str) -> bool:
    """`const fn` is additive: a const fn is callable everywhere a plain fn is, so
    tachyon-web making something const is not a compatibility break. Every other
    difference is."""
    if axum_sig == tach_sig:
        return True
    return tach_sig.startswith("const ") and tach_sig[len("const "):] == axum_sig


def diff_surface(tach_api, axum_api) -> tuple[list[Finding], list[str], int]:
    """Compares axum's public surface against tachyon-web's. Returns
    (findings, extension paths, number of exactly-matching axum paths)."""
    findings: list[Finding] = []
    matched = 0
    tach_by_name = defaultdict(list)
    for (ns, path) in tach_api:
        tach_by_name[(ns, path.split("::")[-1])].append(path)

    for key in sorted(axum_api):
        ns, path = key
        a = axum_api[key]
        t = tach_api.get(key)
        if t is None:
            elsewhere = tach_by_name.get((ns, path.split("::")[-1]))
            hint = ("reachable in tachyon-web at " + ", ".join(sorted(elsewhere))
                    if elsewhere else "no item of this name anywhere in tachyon-web")
            findings.append(Finding(
                "PATH", f"({ns}) axum::{path}",
                f"axum exposes this public path; `use tachyon_web::{path};` does not resolve.",
                hint))
            continue
        if t.kind != a.kind:
            findings.append(Finding("KIND", f"({ns}) {path}",
                                    f"axum: {a.kind}, tachyon-web: {t.kind}"))
            continue
        if not sig_compatible(a.sig, t.sig):
            findings.append(Finding("SIGNATURE", f"({ns}) {path}",
                                    f"axum:    {a.sig}\n    tachyon: {t.sig}"))
            continue
        exact = True
        for mname, msig in sorted(a.members.items()):
            if mname not in t.members:
                findings.append(Finding("MEMBER", f"({ns}) {path}::{mname}",
                                        f"present on axum's `{path}`, absent in tachyon-web",
                                        f"axum: {msig}"))
                exact = False
            elif not sig_compatible(msig, t.members[mname]):
                findings.append(Finding("MEMBER_SIGNATURE", f"({ns}) {path}::{mname}",
                                        f"axum:    {msig}\n    tachyon: {t.members[mname]}"))
                exact = False
        for timpl in sorted(a.traits - t.traits):
            findings.append(Finding("IMPL", f"({ns}) {path}", f"missing: {timpl}"))
            exact = False
        if exact:
            matched += 1

    extensions = sorted(f"({ns}) {path}" for (ns, path) in tach_api if (ns, path) not in axum_api)
    return findings, extensions, matched


# ---------------------------------------------------------------------------
# parity subcommand
# ---------------------------------------------------------------------------

def cmd_parity(args) -> int:
    tach_json, axum_json, core_json, probe_lock = resolve_json(args)
    tach = Crate(load(tach_json), "tachyon-web")
    tach_api = collect_public_api(tach)
    axum_api = merge_axum(axum_crates(axum_json, core_json))

    findings, extensions, matched = diff_surface(tach_api, axum_api)
    findings += diff_features()
    findings += diff_deps(probe_lock)

    allow = load_allowlist()
    allowed = [f for f in findings if f.key() in allow]
    findings = [f for f in findings if f.key() not in allow]

    bar = "=" * 90
    print(bar)
    print("DROP-IN REPLACEABILITY GATE: tachyon-web vs axum + axum-core")
    print(bar)
    print(f"axum public paths:        {len(axum_api)}")
    print(f"tachyon-web public paths: {len(tach_api)}")
    print(f"axum paths matching exactly (path, signature, members, impls): {matched}")

    by_code = defaultdict(list)
    for f in findings:
        by_code[f.code].append(f)
    for code in sorted(by_code, key=lambda c: (-len(by_code[c]), c)):
        print(f"\n{'-' * 90}\n{code}  ({len(by_code[code])})\n{'-' * 90}")
        for f in by_code[code]:
            print(f"\n{f}")

    if args.show_extensions:
        print(f"\n{'-' * 90}\nEXTENSION  ({len(extensions)})  tachyon-only, never a compat gap\n{'-' * 90}")
        for e in extensions:
            print(f"  {e}")

    fatal = [f for f in findings if f.code in FATAL_CODES]
    print("\n" + bar)
    print(f"SUMMARY: {matched}/{len(axum_api)} axum paths fully match, "
          f"{len(fatal)} blocking finding(s), {len(extensions)} tachyon-only item(s), "
          f"{len(allowed)} allowlisted")
    if not args.show_extensions and extensions:
        print(f"(pass --show-extensions to list the {len(extensions)} tachyon-only items)")
    print(bar)

    if args.json:
        Path(args.json).write_text(json.dumps({
            "axum_paths": len(axum_api), "tachyon_paths": len(tach_api), "matched": matched,
            "findings": [{"code": f.code, "path": f.path, "detail": f.detail, "hint": f.hint}
                         for f in findings],
            "extensions": extensions,
        }, indent=2))
        print(f"wrote {args.json}")

    if fatal:
        print(f"\nGATE FAILED: {len(fatal)} finding(s) block drop-in replacement. "
              "A project cannot swap axum for tachyon-web unmodified.", file=sys.stderr)
        return 1
    print("\nGATE PASSED: every axum public path resolves in tachyon-web with the same "
          "kind, signature, members and trait impls; features and shared public "
          "dependencies line up.")
    return 0


# ---------------------------------------------------------------------------
# docs subcommand: enforced public-API doc footers
# ---------------------------------------------------------------------------

def classify_for_docs(tach_api, axum_api) -> dict[int, tuple[str, str | None, dict]]:
    """item_id -> (kind, axum_path_or_None, entry-ish info) for every public
    tachyon-web item defined in this crate. An item counts as parity if *any* of
    the paths it is reachable at is also an axum public path, so a re-export
    doesn't change how it's documented."""
    out: dict[int, tuple[str, str | None, Entry]] = {}
    for (ns, path), e in tach_api.items():
        if e.item_id is None or e.span is None:
            continue
        axum_path = path if (ns, path) in axum_api else None
        prev = out.get(e.item_id)
        if prev is None:
            out[e.item_id] = ("parity" if axum_path else "extension", axum_path, e)
        elif axum_path and prev[1] is None:
            out[e.item_id] = ("parity", axum_path, e)
        elif axum_path and prev[1] and len(axum_path) < len(prev[1]):
            out[e.item_id] = ("parity", axum_path, e)
    return out


def is_doc_hidden(attrs) -> bool:
    for a in attrs or ():
        s = a if isinstance(a, str) else json.dumps(a)
        if "doc(hidden)" in s.replace(" ", ""):
            return True
    return False


DECL_TOKENS = {
    "struct": ("struct ",), "union": ("union ",), "enum": ("enum ",),
    "trait": ("trait ",), "trait_alias": ("trait ",), "function": ("fn ",),
    "type_alias": ("type ",), "constant": ("const ",), "static": ("static ",),
    "macro": ("macro_rules!", "macro "), "proc_macro": ("fn ", "macro "),
}


def anchor_line(lines: list[str], span_line: int, kind: str, name: str) -> int | None:
    """The 0-indexed line carrying this item's declaration, or None.

    Usually that is exactly the span rustdoc reported. Items emitted by a
    `macro_rules!` invocation instead get the *invocation's* span, shared by every
    item the macro produced. Many such invocations still spell the declaration out
    in their body (`composite_rejection! { /// docs\n pub enum JsonRejection {...} }`),
    so fall back to a unique `<keyword> <name>` line -- and give up rather than
    guess if it is not unique.
    """
    tokens = DECL_TOKENS.get(kind, ())
    if 0 <= span_line < len(lines):
        stripped = lines[span_line].strip()
        if any(tok in stripped for tok in tokens):
            return span_line
    pat = re.compile(r"(?:" + "|".join(re.escape(t.strip()) for t in tokens) + r")\s+" +
                     re.escape(name) + r"\b")
    hits = [i for i, ln in enumerate(lines) if pat.search(ln)]
    return hits[0] if len(hits) == 1 else None


def doc_block_bounds(lines: list[str], item_line: int) -> tuple[int, int] | None:
    """Given the 0-indexed line an item declaration starts on, walk upward over its
    attribute run and return the [start, end) slice of its `///` doc block.

    `end` is where the footer belongs. start == end means "no doc block yet; open
    one here". Returns None only when the attribute run cannot be parsed
    unambiguously, so `--fix` never edits a region it does not understand.
    """
    i = item_line - 1
    depth = 0
    while i >= 0:
        s = lines[i].strip()
        if depth == 0 and s.startswith("///"):
            j = i
            while j - 1 >= 0 and lines[j - 1].strip().startswith("///"):
                j -= 1
            return (j, i + 1)
        if not s:
            return (i + 1, i + 1)
        depth += s.count("]") - s.count("[")
        if depth < 0:
            return None
        if depth == 0 and not (s.startswith("#[") or s.startswith("#![")):
            return (i + 1, i + 1)
        i -= 1
    return (0, 0)


def expected_footer(kind: str, axum_path: str | None) -> str:
    if kind == "parity":
        return PARITY_FOOTER.format(axum_path=f"axum::{axum_path}")
    return EXTENSION_FOOTER


def footer_problem(docs: str | None, want: str) -> str | None:
    """Checks the *rendered* doc string, so the verdict is independent of how the
    item was written (hand-written, `#[doc = ...]`, or macro-generated). Returns
    None when correct, otherwise a short reason."""
    text = (docs or "").rstrip()
    found = [ln for ln in text.splitlines() if FOOTER_RE.match("/// " + ln)]
    if not found:
        return "MISSING-FOOTER"
    if len(found) > 1:
        return "DUPLICATE-FOOTER"
    if text.splitlines()[-1] != want:
        return "WRONG-FOOTER" if found[0] != want else "FOOTER-NOT-LAST"
    body = text[: -len(want)]
    if body and not body.endswith("\n\n"):
        return "FOOTER-NOT-SEPARATED"
    return None


def cmd_docs(args) -> int:
    tach_json, axum_json, core_json, _ = resolve_json(args)
    tach = Crate(load(tach_json), "tachyon-web")
    tach_api = collect_public_api(tach)
    axum_api = merge_axum(axum_crates(axum_json, core_json))
    classified = classify_for_docs(tach_api, axum_api)

    n_parity = sum(1 for k, _, _ in classified.values() if k == "parity")
    bar = "=" * 90
    print(bar)
    print("PUBLIC API DOC FOOTERS" + ("  (--fix)" if args.fix else "  (--check)"))
    print(bar)
    print(f"public items classified: {len(classified)} "
          f"({n_parity} axum-parity, {len(classified) - n_parity} tachyon-only)")
    print("footer format (exact; --fix regenerates it, nothing else is accepted):")
    print(f"  parity:    /// {PARITY_FOOTER.format(axum_path='axum::extract::Json')}")
    print(f"  extension: /// {EXTENSION_FOOTER}")
    print("It must be the last doc line, separated from the prose by one blank `///`.")

    ok, undocumented = 0, []
    macro_generated: list[str] = []
    problems: list[str] = []
    per_file: dict[Path, list] = defaultdict(list)

    for kind, axum_path, e in classified.values():
        if is_doc_hidden(e.attrs):
            continue
        want = expected_footer(kind, axum_path)
        reason = footer_problem(e.docs, want)
        span = e.span or {}
        rel = span.get("filename") or "<no span>"
        line = (span.get("begin") or [0])[0]
        where = f"{rel}:{line}"
        prose = [ln for ln in (e.docs or "").splitlines()
                 if ln.strip() and not FOOTER_RE.match("/// " + ln)]
        if not prose:
            undocumented.append(where)
        if reason is None:
            ok += 1
            continue
        f = REPO_ROOT / rel
        if not span or f.suffix != ".rs" or not f.exists():
            macro_generated.append(f"{where}  ({reason}; no editable source span)")
            continue
        per_file[f].append((line - 1, span["begin"][1] - 1, e.kind, want, reason, where, e.name))

    fixed = 0
    for f in sorted(per_file):
        lines = f.read_text().splitlines()
        edits = []
        # Resolve every anchor first, then work bottom-up: an anchor can sit far
        # from the span rustdoc reported, so the span order is not edit-safe.
        resolved = []
        for item_line, col, kind, want, reason, where, name in per_file[f]:
            anchor = anchor_line(lines, item_line, kind, name)
            if anchor is None:
                macro_generated.append(f"{where}  `{name}` ({reason}; generated by a macro -- "
                                       f"add the footer in the macro definition)")
                continue
            if anchor != item_line:
                col = len(lines[anchor]) - len(lines[anchor].lstrip())
            resolved.append((anchor, col, kind, want, reason, f"{f.relative_to(REPO_ROOT)}:{anchor + 1}"))
        for item_line, col, kind, want, reason, where in sorted(resolved, reverse=True):
            bounds = doc_block_bounds(lines, item_line)
            if bounds is None:
                problems.append(f"[AMBIGUOUS] {where}: attribute run could not be parsed; "
                                f"add the footer by hand:\n    /// {want}")
                continue
            start, end = bounds
            indent = " " * col
            block = [ln for ln in lines[start:end] if not FOOTER_RE.match(ln)]
            while block and block[-1].strip() == "///":
                block.pop()
            if block:
                block.append(f"{indent}///")
            block.append(f"{indent}/// {want}")
            if args.fix:
                edits.append((start, end, block))
                fixed += 1
            else:
                problems.append(f"[{reason}] {where}\n    expected last doc line: /// {want}")
        if args.fix and edits:
            for start, end, block in edits:  # descending, so earlier edits don't shift later ones
                lines[start:end] = block
            f.write_text("\n".join(lines) + "\n")

    if macro_generated:
        print(f"\n{len(macro_generated)} macro-generated item(s) --fix cannot touch:")
        for m in sorted(macro_generated):
            print(f"  {m}")

    if args.fix:
        print(f"\nrewrote footers on {fixed} item(s); {ok} were already correct")
        for pr in problems:
            print(pr)
        if undocumented:
            print(f"\nWARNING: {len(undocumented)} public item(s) have no prose documentation "
                  f"beyond the footer:")
            for u in sorted(undocumented)[:40]:
                print(f"  {u}")
            if len(undocumented) > 40:
                print(f"  ... and {len(undocumented) - 40} more")
        print("\nnow run: cargo fmt --all && cargo doc --all-features --no-deps")
        return 1 if (macro_generated or problems) else 0

    if problems or macro_generated:
        if problems:
            print(f"\n{len(problems)} editable doc-footer problem(s):\n")
            for pr in problems:
                print(pr)
        total = len(problems) + len(macro_generated)
        print(f"\n{bar}\nDOC CHECK FAILED: {total} item(s) wrong, {ok} correct.")
        print("Run `python3 scripts/api_diff.py docs --fix` for the editable ones.")
        return 1
    print(f"\nDOC CHECK PASSED: all {ok} public items carry the correct footer.")
    if undocumented:
        print(f"({len(undocumented)} carry only the footer and no prose documentation)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def resolve_json(args) -> tuple[Path, Path, Path, Path | None]:
    """Returns (tachyon.json, axum.json, axum_core.json, probe Cargo.lock|None),
    building whatever isn't supplied or already cached."""
    if args.json_files:
        t, a, c = (Path(p) for p in args.json_files)
        return t, a, c, None
    cache = Path(args.cache).resolve() if args.cache else None
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
    # `docs --fix` edits src/ using the line spans in this JSON, so it must never
    # run against a cached document from before an earlier edit -- stale spans
    # would silently skip items whose declaration has shifted.
    tach_json = build_tachyon_json(cache, force=getattr(args, "fix", False))
    work = cache if cache else Path(tempfile.mkdtemp(prefix="tachyon-api-diff-"))
    axum_json, core_json, lock = build_axum_json(
        lock_versions(REPO_ROOT / "Cargo.lock").get("axum") or _die("axum not in Cargo.lock"), work)
    return tach_json, axum_json, core_json, lock


def _die(msg):
    raise RuntimeError(msg)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("json_files", nargs="*",
                       help="tachyon_web.json axum.json axum_core.json (skip the builds)")
        p.add_argument("--cache", metavar="DIR",
                       help="reuse/keep built rustdoc JSON and the axum probe crate here")

    p_par = sub.add_parser("parity", help="drop-in replaceability gate (default)")
    common(p_par)
    p_par.add_argument("--show-extensions", action="store_true",
                       help="list every tachyon-only public path")
    p_par.add_argument("--json", metavar="FILE", help="also write a machine-readable report")
    p_par.set_defaults(func=cmd_parity)

    p_doc = sub.add_parser("docs", help="public-API doc-footer lint")
    common(p_doc)
    g = p_doc.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="report problems, exit non-zero (default)")
    g.add_argument("--fix", action="store_true", help="rewrite footers in src/")
    p_doc.set_defaults(func=cmd_docs)

    argv = sys.argv[1:]
    if not argv or (argv[0] not in ("parity", "docs", "-h", "--help")):
        argv = ["parity"] + argv
    args = parser.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
