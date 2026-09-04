#!/usr/bin/env python3
"""Replay the whole inkson stylesheet cascade in a real browser and diff it.

Screenshots cannot prove a stylesheet refactor is behaviour-preserving: the
interesting regressions are a single declaration that changed which rule wins,
and they hide in states the screenshot never reaches. This harness compares
*computed styles* instead.

How it works:

1. The injection order is read from `src/app/mod.rs` (the `include_str!` list
   inside the `*_STYLE` layer constants), so the replay always
   uses the real order rather than a hand-maintained copy of it. The same
   extraction runs against a git ref for the "before" side.
2. Every selector in either stylesheet is turned into a DOM probe: combinators
   become nesting, classes/ids/attributes/tag names are materialised,
   pseudo-classes and pseudo-elements are dropped (they only ever narrow the
   match, and dropping them consistently on both sides keeps the comparison
   fair). Every compound of a complex selector also becomes a probe of its
   own, so `A B` contributes probes for `A`, `B` and `A B`.
3. Both stylesheets are measured against the same probe tree, and the report
   lists every `(probe, property)` whose computed value differs.

Only `getComputedStyle` is compared, so the result is exact for anything the
cascade decides and blind to nothing except pseudo-class states.

Usage:
    python scripts/css_cascade_replay.py --before HEAD --out target/cascade
    # then open <out>/cascade_replay.html and call runAt(330) / runAt(1280)
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

INKSON = pathlib.Path(__file__).resolve().parents[1]
APP_MOD = "src/app/mod.rs"
INCLUDE = re.compile(r'include_str!\("\.\./(styles/[^"]+)"\)')
COMMENT = re.compile(r"/\*.*?\*/", re.S)


def read_ref(ref: str | None, rel: str) -> str:
    if ref is None:
        return (INKSON / rel).read_text(encoding="utf-8")
    out = subprocess.run(
        ["git", "show", f"{ref}:{rel}"],
        cwd=INKSON,
        capture_output=True,
    )
    if out.returncode != 0:
        raise SystemExit(f"git show {ref}:{rel} failed: {out.stderr.decode(errors='replace')}")
    return out.stdout.decode("utf-8")


def style_set(ref: str | None) -> list[tuple[str, str]]:
    """Ordered `(relative path, css text)` for one revision."""
    mod_rs = read_ref(ref, APP_MOD)
    order = INCLUDE.findall(mod_rs)
    if not order:
        raise SystemExit(f"no include_str! stylesheet list found in {APP_MOD}")
    return [(rel, read_ref(ref, f"src/{rel}")) for rel in order]


def yoface_prelude() -> list[tuple[str, str]]:
    """The two vendor sheets injected before the app's own stylesheets."""
    root = pathlib.Path.home() / ".cargo" / "git" / "checkouts"
    found: list[tuple[str, str]] = []
    for name in ("tokens.css", "button.css"):
        for path in sorted(root.glob(f"yoface-*/*/src/**/{name}")):
            found.append((f"yoface/{name}", path.read_text(encoding="utf-8")))
            break
    return found


# --- selector -> DOM probe ------------------------------------------------

PSEUDO = re.compile(r"::?[-\w]+(\([^()]*(?:\([^()]*\)[^()]*)*\))?")
ATTR = re.compile(r"\[\s*([-\w]+)\s*(?:([~^$*|]?=)\s*(\"[^\"]*\"|'[^']*'|[^\]]+))?\s*\]")
COMPOUND = re.compile(r"([-\w]+)?((?:[.#][-\w]+|\[[^\]]*\])*)")


def split_selector_list(prelude: str) -> list[str]:
    parts, depth, buf = [], 0, []
    for char in prelude:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def parse_compound(text: str) -> dict | None:
    """`div.a#b[c=d]` -> a description of one element."""
    text = PSEUDO.sub("", text).strip()
    if not text or text in ("*", ">", "+", "~"):
        return None
    node: dict = {"tag": "div", "classes": [], "attrs": {}}
    attrs = ATTR.findall(text)
    for name, op, value in attrs:
        value = value.strip().strip("\"'")
        # A prefix/suffix/substring match is satisfied by the literal itself.
        node["attrs"][name] = value if op else ""
    text = ATTR.sub("", text)
    tag = re.match(r"^[-\w]+", text)
    if tag:
        # `@keyframes` steps (`0%`, `from`) reach here as bare words; anything
        # that is not a legal element name is not a selector at all.
        if not re.fullmatch(r"[A-Za-z][-\w]*", tag.group(0)):
            return None
        node["tag"] = tag.group(0)
        text = text[tag.end():]
    for token in re.findall(r"([.#])([-\w]+)", text):
        if token[0] == ".":
            node["classes"].append(token[1])
        else:
            node["attrs"]["id"] = token[1]
    if node["tag"] in ("html", "body", ":root"):
        node["tag"] = "div"
    if not node["classes"] and not node["attrs"] and node["tag"] == "div":
        return None
    return node


def selector_chains(css: str) -> list[list[dict]]:
    """Every selector in `css`, as a chain of element descriptions."""
    css = COMMENT.sub("", css)
    chains: list[list[dict]] = []
    depth = 0
    start = 0
    in_keyframes = 0
    for index, char in enumerate(css):
        if char == "{":
            if depth <= 1:
                prelude = css[start:index].strip()
                if prelude.startswith("@keyframes") or prelude.startswith("@-"):
                    in_keyframes = depth + 1
                if not prelude.startswith("@") and not in_keyframes:
                    for selector in split_selector_list(prelude):
                        chain = [
                            node
                            for node in (
                                parse_compound(part)
                                for part in re.split(r"\s*[>+~]\s*|\s+", selector)
                            )
                            if node
                        ]
                        if chain:
                            chains.append(chain)
            depth += 1
            start = index + 1
        elif char == "}":
            depth = max(0, depth - 1)
            if in_keyframes and depth < in_keyframes:
                in_keyframes = 0
            start = index + 1
    return chains


def probe_set(sets: list[list[tuple[str, str]]]) -> list[list[dict]]:
    seen: dict[str, list[dict]] = {}
    for style in sets:
        for _rel, css in style:
            for chain in selector_chains(css):
                # The whole chain, plus every suffix, so a rule that only
                # needs the leaf compound is exercised on its own too.
                for start in range(len(chain)):
                    part = chain[start:]
                    key = json.dumps(part, sort_keys=True)
                    seen.setdefault(key, part)
    return list(seen.values())


PAGE = """<meta charset="utf-8">
<title>inkson cascade replay</title>
<style>
  html, body { margin: 0; padding: 0; }
  iframe { position: absolute; left: -99999px; top: 0; border: 0; }
  #out { font: 12px/1.5 monospace; white-space: pre-wrap; padding: 12px; }
</style>
<div id="out">ready - call runAt(width)</div>
<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("data").textContent);

// Media queries resolve against the *viewport*, so each width gets its own
// same-origin iframe rather than a resized browser window: that keeps the
// replay independent of how the tool happens to size the pane.
function buildFrame(width, theme, lang) {
  const frame = document.createElement("iframe");
  frame.style.width = width + "px";
  frame.style.height = "900px";
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  doc.open();
  doc.write("<!doctype html><html><head></head><body></body></html>");
  doc.close();
  doc.documentElement.setAttribute("data-theme", theme);
  doc.documentElement.setAttribute("data-lang", lang);
  const leaves = [];
  for (const chain of DATA.probes) {
    let parent = doc.body;
    let leaf = null;
    for (const node of chain) {
      const el = doc.createElement(node.tag);
      for (const cls of node.classes) el.classList.add(cls);
      for (const [name, value] of Object.entries(node.attrs)) {
        try { el.setAttribute(name, value); } catch (_) {}
      }
      parent.appendChild(el);
      parent = el;
      leaf = el;
    }
    leaves.push(leaf);
  }
  const sheet = doc.createElement("style");
  doc.head.appendChild(sheet);
  return { frame, doc, leaves, sheet };
}

function measure(ctx, css) {
  ctx.sheet.textContent = css;
  const view = ctx.frame.contentWindow;
  const rows = [];
  for (const leaf of ctx.leaves) {
    const cs = view.getComputedStyle(leaf);
    const values = new Array(cs.length);
    for (let i = 0; i < cs.length; i++) {
      // Property names are `[a-z-]+`, so the first "|" always splits
      // the name from the value even when the value contains one.
      values[i] = cs[i] + "|" + cs.getPropertyValue(cs[i]);
    }
    rows.push(values);
  }
  return rows;
}

function toMap(values) {
  const map = new Map();
  for (const entry of values) {
    const cut = entry.indexOf("|");
    map.set(entry.slice(0, cut), entry.slice(cut + 1));
  }
  return map;
}

function runOnce(width, theme, lang) {
  const ctx = buildFrame(width, theme, lang);
  const a = measure(ctx, DATA.a);
  const b = measure(ctx, DATA.b);
  ctx.frame.remove();
  const diffs = [];
  for (let i = 0; i < a.length; i++) {
    const left = toMap(a[i]);
    const right = toMap(b[i]);
    for (const [prop, value] of left) {
      const other = right.get(prop);
      if (other !== value) {
        diffs.push({ probe: DATA.labels[i], prop, before: value, after: other });
      }
    }
    for (const [prop, value] of right) {
      if (!left.has(prop)) diffs.push({ probe: DATA.labels[i], prop, before: undefined, after: value });
    }
  }
  return diffs;
}

function runAt(width) {
  const runs = {};
  for (const [theme, lang] of [["light", "en"], ["dark", "zh"]]) {
    runs[theme] = runOnce(width, theme, lang);
  }
  window.__report = { width, probes: DATA.probes.length, runs };
  const lines = [];
  for (const [theme, diffs] of Object.entries(runs)) {
    lines.push(`${width}px ${theme}: ${diffs.length} diff(s)`);
    const grouped = new Map();
    for (const d of diffs) {
      if (!grouped.has(d.probe)) grouped.set(d.probe, []);
      grouped.get(d.probe).push(`${d.prop}: ${d.before} -> ${d.after}`);
    }
    for (const [probe, items] of grouped) {
      lines.push(`  ${probe}`);
      for (const item of items) lines.push(`      ${item}`);
    }
  }
  const text = lines.join(String.fromCharCode(10));
  document.getElementById("out").textContent = text;
  return text;
}
window.runAt = runAt;
</script>
"""


def label(chain: list[dict]) -> str:
    parts = []
    for node in chain:
        text = node["tag"]
        text += "".join(f".{c}" for c in node["classes"])
        text += "".join(
            f"[{k}={v}]" if v else f"[{k}]" for k, v in node["attrs"].items()
        )
        parts.append(text)
    return " ".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", default="HEAD", help="git ref for the 'before' side")
    parser.add_argument("--out", default="target/cascade", help="output directory")
    args = parser.parse_args()

    prelude = yoface_prelude()
    before = prelude + style_set(args.before)
    after = prelude + style_set(None)
    probes = probe_set([before, after])
    data = {
        "a": "\n".join(css for _rel, css in before),
        "b": "\n".join(css for _rel, css in after),
        "probes": probes,
        "labels": [label(chain) for chain in probes],
    }
    out_dir = INKSON / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    page = out_dir / "cascade_replay.html"
    page.write_text(
        PAGE.replace("__DATA__", json.dumps(data).replace("</", "<\\/")),
        encoding="utf-8",
    )
    print(f"before: {len(before)} sheet(s)  after: {len(after)} sheet(s)  probes: {len(probes)}")
    print(page.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
