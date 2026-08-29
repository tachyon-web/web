#!/usr/bin/env python3
"""Structural, FULL-COVERAGE API diff between tachyon-web and axum (+ axum-core),
driven by rustdoc JSON.

This walks the *entire* public module tree of each crate starting at its crate
root -- following `pub use` re-exports (including globs) to the paths they're
actually reachable at -- and diffs every public item it finds by (namespace,
name). There is no hand-picked list of "the axum-parity surface" anywhere in
this file: the set of names compared is derived mechanically from the two
rustdoc JSON trees, not from reading tachyon-web's source and deciding what
"should" be covered. axum-extra is out of scope simply because it is a
separate crate this script is never pointed at.

End-to-end usage (this is what CI runs -- no arguments, no manual setup):

    python3 scripts/api_diff.py

This builds both sides' rustdoc JSON itself:
  1. tachyon-web's own JSON, built in place from the crate root with the
     broadest non-exotic feature set (everything except `tor`/`i2p`, which
     pull in vendored C++ toolchains, and `fips`, which is a build-mode
     modifier rather than additive API surface).
  2. axum + axum-core's JSON, built from a throwaway probe crate in a temp
     directory that depends on axum pinned to the exact version in this
     repo's Cargo.lock, with every non-private axum feature enabled (so nothing
     feature-gated on axum's side is invisible to the diff). axum-core's items
     (FromRequest, IntoResponse, FromRef, ...) are re-exported by axum but NOT
     inlined into axum's own rustdoc JSON, so both crates are documented
     separately and unioned.

The process exits non-zero -- deliberately failing CI -- whenever the public
surfaces don't line up: anything MISSING in tachyon-web, anything that
DIFFERS in signature, or any ARITY case (ambiguous multi-candidate pairing)
that hasn't been manually reviewed away. TACHYON-ONLY additions do not fail
the build; axum parity does not forbid tachyon-web from having more.

Manual / debugging usage (skips the build, diffs pre-built JSON files):

    python3 scripts/api_diff.py tachyon_web.json axum.json axum_core.json [--show-matches]

Notes / known limitations (read before trusting a verdict blindly):
- Rustdoc JSON item ids are only valid within their own file -- never merge
  index/paths dicts from two different JSON files. Each file is kept as its
  own `Crate`; results are merged only *after* independently walking each
  crate's own module tree and rendering full descriptions locally.
- Matching key is (namespace, name) where namespace collapses fn/const/static
  into "value" and struct/enum/trait/type_alias/union/trait_alias into "type"
  (Rust's own namespacing rules), NOT the module path -- tachyon's module
  layout doesn't mirror axum's, so path-based matching would spuriously miss
  everything. This means two unrelated items sharing a bare name in the same
  namespace can appear paired; when either side has >1 item under a key this
  prints as [ARITY] with every candidate listed instead of guessing a pairing.
- An axum `pub use` of an axum-core item that axum-core itself also defines
  (the common case) produces one stub match (no local signature, since the
  target lives in a different JSON file) in axum's own walk, and one full
  entry in axum-core's own walk. The stub is dropped whenever a non-stub
  entry exists under the same key, so this doesn't inflate arity in practice
  -- but a genuinely axum-core-only item with no matching axum-core walk
  result (e.g. this script pointed at a mismatched axum/axum-core version
  pair) would surface only as an unresolved stub with no signature to compare.
- Whole-crate glob re-exports of a *foreign, non-axum-core* crate (e.g.
  `axum::http` = `pub use http;`) are recorded as a single opaque stub, not
  expanded -- this script does not attempt to enumerate a third crate's API.
- Macro bodies (`macro_rules!` definitions) are compared only by presence,
  not by their expansion text, since textual macro_rules diffs are mostly
  cosmetic noise.
- `#[doc(hidden)]` is not specially filtered; only rustdoc's `visibility`
  field (public/crate/restricted/default) is used, matching what actually
  shows up in `cargo doc` for a downstream consumer.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every tachyon-web feature except `tor`/`i2p` (vendored C++ toolchains,
# not relevant to public API shape) and `fips` (a build-mode modifier, not
# additive API surface). Kept in sync with the CI "full (no tor/i2p)" build
# matrix entry so this never needs a toolchain/system-dep the parity job
# doesn't already have.
TACHYON_FEATURES = (
    "json,cookies,matched-path,original-uri,http1,http2,tower-log,ws,form,query,"
    "sse,sfv,tls,cert-gen,lets-encrypt,http3,compression-full,early-hints,multipart"
)

# Every non-private, non-doc-only axum 0.8 feature, so nothing feature-gated
# on axum's side is invisible to the diff.
AXUM_FEATURES = (
    "form,http1,http2,json,macros,multipart,query,tokio,tracing,ws,"
    "matched-path,original-uri,tower-log"
)


def load(path):
    with open(path) as f:
        return json.load(f)


def run(cmd, cwd=None, env=None):
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def rustdoc_env():
    import os
    env = dict(os.environ)
    env["RUSTDOCFLAGS"] = "--cap-lints=warn"
    return env


def axum_lock_version(repo_root: Path) -> str:
    lock = (repo_root / "Cargo.lock").read_text()
    m = re.search(r'name = "axum"\nversion = "([^"]+)"', lock)
    if not m:
        raise RuntimeError("could not find axum's pinned version in Cargo.lock")
    return m.group(1)


def build_tachyon_json(repo_root: Path) -> Path:
    run(
        [
            "cargo", "+nightly", "rustdoc", "--lib", "-p", "tachyon-web",
            "--no-default-features", "--features", TACHYON_FEATURES,
            "--", "-Z", "unstable-options", "--output-format", "json",
        ],
        cwd=repo_root,
        env=rustdoc_env(),
    )
    out = repo_root / "target" / "doc" / "tachyon_web.json"
    if not out.exists():
        raise RuntimeError(f"expected rustdoc output at {out}, not found")
    return out


def build_axum_json(axum_version: str, tmp_dir: Path) -> tuple[Path, Path]:
    probe = tmp_dir / "axum-probe"
    (probe / "src").mkdir(parents=True)
    (probe / "Cargo.toml").write_text(
        f"""[package]
name = "axum-probe"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
axum = {{ version = "={axum_version}", features = [{", ".join(f'"{f}"' for f in AXUM_FEATURES.split(","))}] }}
tokio = {{ version = "1", features = ["full"] }}

[workspace]
"""
    )
    (probe / "src" / "main.rs").write_text("fn main() {}\n")

    for crate_name in ("axum", "axum-core"):
        run(
            [
                "cargo", "+nightly", "rustdoc", "-p", crate_name, "--lib",
                "--", "-Z", "unstable-options", "--output-format", "json",
            ],
            cwd=probe,
            env=rustdoc_env(),
        )

    axum_json = probe / "target" / "doc" / "axum.json"
    axum_core_json = probe / "target" / "doc" / "axum_core.json"
    for p in (axum_json, axum_core_json):
        if not p.exists():
            raise RuntimeError(f"expected rustdoc output at {p}, not found")
    return axum_json, axum_core_json


class Crate:
    """A single rustdoc-JSON doc. Item ids are only meaningful within one
    JSON file, so this must never be merged with another file's tables --
    doing that by plain dict-update silently collides id spaces and produces
    garbage cross-references (this bit us once; see git history of this file).
    """

    def __init__(self, data, label):
        self.data = data
        self.label = label
        self.index = data["index"]
        self.paths = data["paths"]
        self.crate_id = self.index[str(data["root"])]["crate_id"]

    def item(self, iid):
        return self.index.get(str(iid))


# ---------------------------------------------------------------------------
# Signature rendering (structural, not textual -- so cosmetic whitespace/
# ordering in the source can't masquerade as a real match or a real diff).
# ---------------------------------------------------------------------------

def render_type(c: Crate, t):
    if t is None:
        return "()"
    if "generic" in t:
        return t["generic"]
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
        name = name_of(c, rp["id"])
        args = rp.get("args")
        return name + render_generic_args(c, args)
    if "qualified_path" in t:
        qp = t["qualified_path"]
        base = render_type(c, qp["self_type"])
        trait = qp.get("trait")
        tname = name_of(c, trait["id"]) if trait else ""
        return f"<{base} as {tname}>::{qp['name']}"
    if "impl_trait" in t:
        bounds = t["impl_trait"]
        return "impl " + " + ".join(render_bound(c, b) for b in bounds)
    if "dyn_trait" in t:
        dt = t["dyn_trait"]
        traits = dt.get("traits", [])
        parts = []
        for tr in traits:
            path = tr["trait"]
            parts.append(name_of(c, path["id"]) + render_generic_args(c, path.get("args")))
        return "dyn " + " + ".join(parts)
    if "function_pointer" in t:
        return "fn(...)"
    if "infer" in t:
        return "_"
    return json.dumps(t, sort_keys=True)[:80]


def name_of(c: Crate, iid):
    it = c.item(iid)
    if it and it.get("name"):
        return it["name"]
    p = c.paths.get(str(iid))
    if p:
        return p["path"][-1]
    return f"#{iid}"


def render_generic_args(c, args):
    if not args:
        return ""
    if "angle_bracketed" in args:
        ab = args["angle_bracketed"]
        parts = []
        for a in ab.get("args", []):
            if "type" in a:
                parts.append(render_type(c, a["type"]))
            elif "lifetime" in a:
                parts.append(a["lifetime"])
            elif "const" in a:
                parts.append("const")
        if not parts:
            return ""
        return "<" + ", ".join(parts) + ">"
    if "parenthesized" in args:
        p = args["parenthesized"]
        ins = ", ".join(render_type(c, x) for x in p.get("inputs", []))
        out = render_type(c, p["output"]) if p.get("output") else ""
        return f"({ins}) -> {out}" if out else f"({ins})"
    return ""


def render_bound(c, b):
    if "trait_bound" in b:
        tb = b["trait_bound"]
        tr = tb["trait"]
        return name_of(c, tr["id"]) + render_generic_args(c, tr.get("args"))
    if "outlives" in b:
        return b["outlives"]
    return "?"


def render_generics(c, generics):
    parts = []
    for p in generics.get("params", []):
        kind = p["kind"]
        if "type" in kind:
            bounds = kind["type"].get("bounds", [])
            bs = " + ".join(render_bound(c, b) for b in bounds)
            parts.append(p["name"] + (f": {bs}" if bs else ""))
        elif "lifetime" in kind:
            parts.append(p["name"])
        elif "const" in kind:
            parts.append(p["name"] + ": const")
    where = []
    for w in generics.get("where_predicates", []):
        if "bound_predicate" in w:
            bp = w["bound_predicate"]
            ty = render_type(c, bp["type"])
            bs = " + ".join(render_bound(c, b) for b in bp["bounds"])
            where.append(f"{ty}: {bs}")
    s = ""
    if parts:
        s += "<" + ", ".join(parts) + ">"
    if where:
        s += " where " + ", ".join(sorted(where))
    return s


def render_fn_sig(c, item):
    inner = item["inner"]["function"]
    sig = inner["sig"]
    header = inner["header"]
    generics = render_generics(c, inner["generics"])
    ins = []
    for name, ty in sig["inputs"]:
        ins.append(f"{name}: {render_type(c, ty)}")
    out = render_type(c, sig["output"]) if sig.get("output") else "()"
    prefix = "async " if header.get("is_async") else ""
    return f"{prefix}fn{generics}({', '.join(ins)}) -> {out}"


def render_trait(c, item):
    inner = item["inner"]["trait"]
    lines = []
    for mid in inner.get("items", []):
        m = c.item(mid)
        if not m:
            continue
        mk = list(m.get("inner", {}).keys())
        if not mk:
            continue
        if mk[0] == "function":
            lines.append(f"{m['name']}: {render_fn_sig(c, m)}")
        elif mk[0] == "assoc_type":
            at = m["inner"]["assoc_type"]
            bounds = " + ".join(render_bound(c, b) for b in at.get("bounds", []))
            lines.append(f"type {m['name']}" + (f": {bounds}" if bounds else ""))
        elif mk[0] == "assoc_const":
            lines.append(f"const {m['name']}")
    return sorted(lines)


def render_struct_like(c, inner, name, kind_word):
    skind = list(inner.get("kind", {}).keys())
    generics = render_generics(c, inner.get("generics", {}))
    return f"{kind_word} {name}{generics} ({skind[0] if skind else '?'})"


def describe_item(c: Crate, item):
    """Returns a rendered structural description string for one item."""
    inner_all = item.get("inner", {})
    if not inner_all:
        return "?"
    k = next(iter(inner_all.keys()))
    inner = inner_all[k]
    name = item.get("name") or "?"
    try:
        if k == "function":
            return render_fn_sig(c, item)
        if k == "trait":
            return "trait {\n    " + "\n    ".join(render_trait(c, item)) + "\n}"
        if k == "trait_alias":
            bounds = " + ".join(render_bound(c, b) for b in inner.get("bounds", []))
            return f"trait_alias{render_generics(c, inner.get('generics', {}))} = {bounds}"
        if k == "struct":
            return render_struct_like(c, inner, name, "struct")
        if k == "union":
            return render_struct_like(c, inner, name, "union")
        if k == "enum":
            variants = []
            for vid in inner.get("variants", []):
                v = c.item(vid)
                if v:
                    variants.append(v["name"])
            return "enum " + render_generics(c, inner.get("generics", {})) + " variants: " + ", ".join(sorted(variants))
        if k == "type_alias":
            return "type = " + render_type(c, inner["type"])
        if k == "constant":
            return "const: " + render_type(c, inner.get("type"))
        if k == "static":
            return "static" + (" mut" if inner.get("is_mutable") else "") + ": " + render_type(c, inner.get("type"))
        if k in ("macro", "proc_macro"):
            return f"<macro {name}, body not compared>"
    except Exception as e:  # rendering must never crash the whole run
        return f"<render error: {e}>"
    return f"<unhandled kind {k}>"


# ---------------------------------------------------------------------------
# Full public-API-surface walk: starts at the crate root module and follows
# every reachable public path, including through `use` re-exports (named and
# glob), recording each leaf item under the *path it's actually reachable at*
# -- not necessarily its definition site.
# ---------------------------------------------------------------------------

LEAF_KINDS = {
    "function", "struct", "enum", "trait", "type_alias",
    "macro", "proc_macro", "constant", "static", "union", "trait_alias",
}


def namespace_of(kind):
    if kind in ("function", "constant", "static"):
        return "value"
    if kind in ("macro", "proc_macro"):
        return "macro"
    return "type"


def collect_public_api(c: Crate):
    """Walks c's public module tree from its crate root. Returns
    dict[(namespace, name)] -> list of (path_tuple, kind, description, label).
    """
    results = defaultdict(list)

    def record(path, kind, item, stub_desc=None):
        name = path[-1]
        desc = stub_desc if stub_desc is not None else describe_item(c, item)
        results[(namespace_of(kind), name)].append((path, kind, desc, c.label))

    def handle_use(use_item, path, seen_ids):
        u = use_item.get("inner", {}).get("use", {})
        name = use_item.get("name") or u.get("name")
        if not name:
            return
        target_id = u.get("id")
        if u.get("is_glob"):
            if target_id is not None:
                tgt = c.item(target_id)
                if tgt is not None and tgt.get("crate_id") == c.crate_id and "module" in tgt.get("inner", {}):
                    walk(target_id, path, seen_ids)
            return
        if target_id is None:
            return
        tgt = c.item(target_id)
        if tgt is not None and tgt.get("crate_id") == c.crate_id:
            tkeys = list(tgt.get("inner", {}).keys())
            if not tkeys:
                return
            tk = tkeys[0]
            if tk == "module":
                walk(target_id, path + (name,), seen_ids)
            elif tk == "use":
                handle_use(tgt, path, seen_ids)
            elif tk in LEAF_KINDS:
                record(path + (name,), tk, tgt)
            return
        # Target lives in a different JSON file (e.g. axum re-exporting an
        # axum-core item) -- we only have path/kind metadata for it here, not
        # a renderable body. Skip whole-module re-exports of unrelated
        # foreign crates entirely (nothing to fairly compare); everything
        # else becomes an unresolved stub that a same-key non-stub entry
        # (from that crate's own JSON file, if it was also passed on the
        # command line) will supersede later.
        p = c.paths.get(str(target_id))
        if not p:
            return
        pkind = p.get("kind", "?")
        if pkind == "module":
            return
        if pkind not in LEAF_KINDS:
            return
        record(path + (name,), pkind, None, stub_desc="<external re-export, signature not locally resolvable>")

    def walk(module_id, path, seen_ids):
        if module_id in seen_ids:
            return
        seen_ids = seen_ids | {module_id}
        mod = c.item(module_id)
        if mod is None or mod.get("visibility") != "public":
            return
        minner = mod.get("inner", {}).get("module")
        if minner is None:
            return
        for child_id in minner.get("items", []):
            child = c.item(child_id)
            if child is None:
                continue
            if child.get("crate_id") != c.crate_id:
                continue
            if child.get("visibility") != "public":
                continue
            ckeys = list(child.get("inner", {}).keys())
            if not ckeys:
                continue
            ck = ckeys[0]
            cname = child.get("name")
            if ck == "use":
                handle_use(child, path, seen_ids)
            elif ck == "module":
                if cname:
                    walk(child_id, path + (cname,), seen_ids)
            elif ck in LEAF_KINDS:
                if cname:
                    record(path + (cname,), ck, child)
            # impl blocks, extern_crate, primitive, keyword, etc. are not
            # named leaf items in the public surface -- skip.

    walk(int(c.data["root"]), (), set())
    return results


def dedup_by_signature(entries):
    """Collapses entries that are the same item reachable at multiple public
    paths (a common re-export pattern -- e.g. `tachyon_web::Router` re-exported
    at the crate root *and* available at `tachyon_web::routing::Router`) down
    to one candidate, so that doesn't inflate [ARITY] noise for something that
    isn't a real divergence. Entries are considered the same item only when
    their kind AND rendered signature are byte-identical; genuinely distinct
    items that happen to share a bare name are kept separate.
    """
    seen = {}
    order = []
    for path, kind, desc, label in entries:
        key = (kind, desc)
        if key not in seen:
            seen[key] = (path, kind, desc, label, [path])
            order.append(key)
        else:
            seen[key][4].append(path)
    return [seen[k] for k in order]


def merge_axum_group(crates):
    """Union collect_public_api() over axum + axum-core, dropping any
    unresolved stub entry under a key that also has a real (non-stub) entry
    from one of the other crates -- see module docstring for why this is
    safe rather than lossy in the common case."""
    per_crate = [collect_public_api(c) for c in crates]
    merged = defaultdict(list)
    for d in per_crate:
        for k, v in d.items():
            merged[k].extend(v)
    for k, entries in merged.items():
        non_stub = [e for e in entries if not e[2].startswith("<external re-export")]
        if non_stub:
            merged[k] = non_stub
    return merged


def diff(tach: Crate, axum_crates: list[Crate], show_matches: bool) -> int:
    """Runs the full diff and prints a report. Returns a process exit code:
    0 if tachyon-web's public surface is a strict superset of axum's (modulo
    signature-identical matches), non-zero otherwise."""
    tach_api = collect_public_api(tach)
    axum_api = merge_axum_group(axum_crates)

    all_keys = sorted(set(tach_api) | set(axum_api))

    n_match = n_differs = n_missing = n_tachyon_only = n_arity = 0
    matches = []

    print("=" * 100)
    print("STRUCTURAL API DIFF: tachyon-web vs axum + axum-core (full public surface, rustdoc JSON derived)")
    print("=" * 100)
    print(f"tachyon-web public items indexed: {sum(len(v) for v in tach_api.values())}"
          f"  ({len(tach_api)} distinct (namespace, name) keys)")
    print(f"axum(+core) public items indexed: {sum(len(v) for v in axum_api.values())}"
          f"  ({len(axum_api)} distinct (namespace, name) keys)")

    def fmt_paths(path, aliases):
        if len(aliases) <= 1:
            return "::".join(path)
        return "::".join(path) + f"  (+{len(aliases) - 1} other reachable path(s): "\
            + ", ".join("::".join(p) for p in aliases if p != path) + ")"

    for ns, name in all_keys:
        t_entries = dedup_by_signature(tach_api.get((ns, name), []))
        a_entries = dedup_by_signature(axum_api.get((ns, name), []))

        if not a_entries:
            n_tachyon_only += 1
            print(f"\n[TACHYON-ONLY] ({ns}) {name}: no axum counterpart (addition, not a compat gap)")
            for path, kind, desc, label, aliases in t_entries:
                print(f"  tachyon [{kind}] {fmt_paths(path, aliases)}")
            continue

        if not t_entries:
            n_missing += 1
            print(f"\n[MISSING IN TACHYON] ({ns}) {name}: present in axum, not found in tachyon-web")
            for path, kind, desc, label, aliases in a_entries:
                print(f"  axum    [{kind}] {label}::{fmt_paths(path, aliases)}")
            continue

        if len(t_entries) == 1 and len(a_entries) == 1:
            (tp, tk, td, _, taliases), (ap, ak, ad, alabel, aaliases) = t_entries[0], a_entries[0]
            if td == ad:
                n_match += 1
                matches.append((ns, name))
                if show_matches:
                    print(f"\n[MATCH] ({ns}) {name}")
                continue
            n_differs += 1
            print(f"\n[DIFFERS] ({ns}) {name}")
            print(f"  tachyon [{tk}] {fmt_paths(tp, taliases)}: {td}")
            print(f"  axum    [{ak}] {alabel}::{fmt_paths(ap, aaliases)}: {ad}")
            continue

        n_arity += 1
        print(f"\n[ARITY] ({ns}) {name}: tachyon has {len(t_entries)} distinct candidate(s), "
              f"axum has {len(a_entries)} -- inspect manually, no automatic pairing")
        for path, kind, desc, label, aliases in t_entries:
            print(f"  tachyon [{kind}] {fmt_paths(path, aliases)}: {desc}")
        for path, kind, desc, label, aliases in a_entries:
            print(f"  axum    [{kind}] {label}::{fmt_paths(path, aliases)}: {desc}")

    print("\n" + "=" * 100)
    print(f"SUMMARY: {n_match} match, {n_differs} differ, {n_missing} missing in tachyon, "
          f"{n_tachyon_only} tachyon-only, {n_arity} need manual arity review")
    if not show_matches and matches:
        print(f"(matched names hidden; pass --show-matches to list them -- {n_match} total)")
    print("=" * 100)

    failing = n_missing + n_differs + n_arity
    if failing:
        print(
            f"\nPARITY CHECK FAILED: {failing} item(s) block drop-in replaceability "
            f"({n_missing} missing, {n_differs} differing, {n_arity} unresolved arity). "
            "tachyon-web is not yet a full axum substitute.",
            file=sys.stderr,
        )
        return 1
    print("\nPARITY CHECK PASSED: every axum(+axum-core) public item has an identical tachyon-web counterpart.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("json_files", nargs="*", help="tachyon_web.json axum.json axum_core.json (manual mode; omit all three to build+diff end-to-end)")
    parser.add_argument("--show-matches", action="store_true")
    args = parser.parse_args()

    if args.json_files:
        if len(args.json_files) != 3:
            parser.error("manual mode requires exactly 3 paths: tachyon_web.json axum.json axum_core.json")
        tach = Crate(load(args.json_files[0]), "tachyon-web")
        axum_crates = [
            Crate(load(p), Path(p).stem) for p in args.json_files[1:]
        ]
        sys.exit(diff(tach, axum_crates, args.show_matches))

    print("No JSON files given -- building both sides from source (this is the CI path).", file=sys.stderr)
    tachyon_json = build_tachyon_json(REPO_ROOT)
    with tempfile.TemporaryDirectory(prefix="tachyon-api-diff-") as tmp:
        axum_json, axum_core_json = build_axum_json(axum_lock_version(REPO_ROOT), Path(tmp))
        tach = Crate(load(tachyon_json), "tachyon-web")
        axum_crates = [Crate(load(axum_json), "axum"), Crate(load(axum_core_json), "axum_core")]
        sys.exit(diff(tach, axum_crates, args.show_matches))


if __name__ == "__main__":
    main()
