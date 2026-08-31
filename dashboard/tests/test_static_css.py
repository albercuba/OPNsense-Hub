from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STYLE_CSS = ROOT / "dashboard/app/static/style.css"


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
