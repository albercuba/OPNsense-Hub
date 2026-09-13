import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STYLE_CSS = ROOT / "dashboard/app/static/style.css"
HUB_THEME_CSS = ROOT / "dashboard/app/static/hub-theme.css"


# These are existing intentional literals, not token debt:
# - style.css toggle sun rays and white control text are fixed-contrast UI details.
# - hub-theme.css uses fixed white text on colored controls and fixed brand/shell
#   colors that must not vary with the semantic surface tokens.
# Scoped custom-property declarations are token definitions, so they are checked
# separately by the CSS parser and are not direct hardcoded property values.
_ALLOWED_HARDCODED_COLORS = {
    ("style.css", "background: #fff;"),
    ("style.css", "0.36rem 0.36rem 0 0.52rem #fff inset,"),
    ("style.css", "0 -0.6rem 0 -0.3rem #fff,"),
    ("style.css", "0.44rem -0.44rem 0 -0.34rem #fff,"),
    ("style.css", "0.6rem 0 0 -0.3rem #fff,"),
    ("style.css", "0.44rem 0.44rem 0 -0.34rem #fff,"),
    ("style.css", "0 0.6rem 0 -0.3rem #fff,"),
    ("style.css", "-0.44rem 0.44rem 0 -0.34rem #fff,"),
    ("style.css", "-0.6rem 0 0 -0.3rem #fff,"),
    ("style.css", "-0.44rem -0.44rem 0 -0.34rem #fff;"),
    ("style.css", "color: #fff;"),
    ("hub-theme.css", "border-bottom: 1px solid #e8ebed;"),
    ("hub-theme.css", "color: #fff;"),
    ("hub-theme.css", "color: #202326;"),
    ("hub-theme.css", "background: #ededed;"),
    ("hub-theme.css", "border-right: 1px solid #e8ebed;"),
    ("hub-theme.css", "background: #eaf4fe;"),
}


def _raw_colors_outside_theme_blocks(path: Path) -> list[tuple[int, str]]:
    raw_colors = []
    root_depth = 0
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if root_depth == 0 and re.match(
            r":root(?:\[data-theme=\"dark\"\])?\s*\{", stripped
        ):
            root_depth = 1
            continue
        if root_depth:
            root_depth += line.count("{") - line.count("}")
            continue
        if stripped.startswith("--"):
            continue
        if re.search(r"#[0-9a-fA-F]{3,6}\b", line):
            raw_colors.append((line_number, stripped))
    return raw_colors


def test_css_uses_tokens_for_colors_outside_theme_definitions():
    violations = []
    for path in (STYLE_CSS, HUB_THEME_CSS):
        relative_name = path.name
        for line_number, line in _raw_colors_outside_theme_blocks(path):
            if (relative_name, line) not in _ALLOWED_HARDCODED_COLORS:
                violations.append(f"{path}:{line_number}: {line}")
    assert not violations, "Use theme tokens for CSS colors:\n" + "\n".join(violations)


def test_timeline_scroll_panel_keeps_content_clear_of_scrollbar():
    source = STYLE_CSS.read_text()
    selector = ".timeline-scroll-panel"
    start = source.find(selector)
    assert start != -1

    rule = source[start : source.find("}", start)]
    assert "padding-right: 1rem;" in rule
    assert "scrollbar-gutter: stable;" in rule


def test_final_mobile_app_layout_rule_keeps_single_column_layout():
    source = STYLE_CSS.read_text()
    final_mobile = source.rfind("@media (max-width: 900px)")
    assert final_mobile != -1

    final_mobile_block = source[final_mobile:]
    app_layout = final_mobile_block.find(".app-layout")
    assert app_layout != -1

    app_layout_rule = final_mobile_block[app_layout:final_mobile_block.find("}", app_layout)]
    assert "grid-template-columns: 1fr;" in app_layout_rule
