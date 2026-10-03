"""Keep Dioxus's generated WASM entry point single-start after cached builds."""

from pathlib import Path


BOOTSTRAP_MARKER = "globalThis.__wasm_split_main_initSync = initSync;"
BOOTSTRAP_CALL = "__wbg_init({module_or_path:"


def single_bootstrap(source: str) -> str:
    sections = source.split(BOOTSTRAP_MARKER)
    if len(sections) < 2:
        raise RuntimeError("Dioxus web artifact has no recognized bootstrap")
    blocks = [section.strip() for section in sections[1:]]
    if any(block != blocks[0] for block in blocks):
        raise RuntimeError("Dioxus web artifact has conflicting bootstrap blocks")
    if blocks[0].count(BOOTSTRAP_CALL) != 1 or BOOTSTRAP_CALL in sections[0]:
        raise RuntimeError("Dioxus web artifact must initialize WASM exactly once")
    if len(blocks) == 1:
        return source
    return sections[0] + BOOTSTRAP_MARKER + "\n\n" + blocks[0] + "\n"


def normalize_web_bootstrap(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    normalized = single_bootstrap(source)
    if normalized == source:
        return False
    temporary = path.with_suffix(".js.tmp")
    temporary.write_text(normalized, encoding="utf-8", newline="\n")
    temporary.replace(path)
    return True
