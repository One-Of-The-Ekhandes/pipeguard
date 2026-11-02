import sys
from pathlib import Path

from pipeguard.registry import RULES
from pipeguard.scanner import scan
from pipeguard.scoring import score

ROOT = Path(__file__).resolve().parent.parent


def test_vulnerable_example_trips_most_rules():
    result = scan(ROOT / "examples" / "vulnerable")
    assert score(result.findings) == 0
    assert len({f.rule.id for f in result.findings}) >= 30


def test_hardened_example_is_clean():
    result = scan(ROOT / "examples" / "hardened")
    assert result.findings == [] and score(result.findings) == 100


def test_rules_doc_is_up_to_date():
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_rules_doc
    doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert doc == gen_rules_doc.render(), "run: python tools/gen_rules_doc.py"


def test_every_rule_has_fix_and_description():
    for r in RULES.values():
        assert r.description and r.fix and r.title, r.id
