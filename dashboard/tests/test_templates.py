from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEVICE_TEMPLATE = ROOT / "dashboard/app/templates/device.html"


class BackupIntervalOptionParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_backup_interval_options = False
        self.options: list[dict[str, str]] = []
        self.strong_depth = 0
        self.unmatched_strong_closes = 0
        self.backup_now_button_classes: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "datalist" and attrs_dict.get("id") == "backup-interval-unit-options":
            self.in_backup_interval_options = True
        if self.in_backup_interval_options and tag == "option":
            self.options.append(attrs_dict)
        if tag == "button" and attrs_dict.get("formaction", "").endswith(
            "/backup-now"
        ):
            self.backup_now_button_classes = attrs_dict.get("class", "").split()
        if tag == "strong":
            self.strong_depth += 1

    def handle_endtag(self, tag):
        if tag == "datalist" and self.in_backup_interval_options:
            self.in_backup_interval_options = False
        if tag == "strong":
            if self.strong_depth == 0:
                self.unmatched_strong_closes += 1
            else:
                self.strong_depth -= 1


def test_backup_interval_options_are_well_formed():
    parser = BackupIntervalOptionParser()
    parser.feed(DEVICE_TEMPLATE.read_text())

    assert parser.options == [
        {"value": "Hours", "data-unit-value": "hours"},
        {"value": "Days", "data-unit-value": "days"},
        {"value": "Months", "data-unit-value": "months"},
    ]
    assert parser.unmatched_strong_closes == 0


def test_backup_now_uses_green_backup_action_style():
    parser = BackupIntervalOptionParser()
    parser.feed(DEVICE_TEMPLATE.read_text())

    assert "button" in parser.backup_now_button_classes
    assert "backup-action" in parser.backup_now_button_classes
    assert "secondary" not in parser.backup_now_button_classes
