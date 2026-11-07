"""The committed example reports match what the built-in demo produces today.

examples/sample_report.html and examples/sample_result.json are linked from the
README as the complete example report. They come from `granttrace demo`, the only
bundled run whose PATCH checks have authoritative state, so a change to verdicts,
reasons or statistics must regenerate them:

    python scripts/verify_examples.py --update-examples
"""

from __future__ import annotations

import html
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Dict, Tuple

from core import __version__, demo

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
REGENERATE = "regenerate them with: python scripts/verify_examples.py --update-examples"


def _outcomes(report: Dict[str, Any]) -> Dict[Tuple[str, str], Tuple[Any, ...]]:
    return {
        (item["endpoint"], item["check"]): (
            item["verdict"], item["reason"], item["evidence"].get("reason_category"),
        )
        for item in report["results"]
    }


def _findings(report: Dict[str, Any]) -> list:
    return sorted(
        (item["endpoint"], item["type"], item["cwe"], item["severity"], item["details"])
        for item in report["findings"]
    )


class CommittedExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-example-tests-")
        cls.addClassCleanup(temporary.cleanup)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
            code = demo.run_demo(output_dir=temporary.name)
        if code != 0:
            raise AssertionError("Built-in demo failed: " + stderr.getvalue())
        (run,) = Path(temporary.name).glob("run-*")
        cls.fresh = json.loads((run / "granttrace_report.json").read_text(encoding="utf-8"))
        cls.example = json.loads((EXAMPLES / "sample_result.json").read_text(encoding="utf-8"))
        cls.example_html = (EXAMPLES / "sample_report.html").read_text(encoding="utf-8")

    def test_examples_declare_the_current_version(self):
        self.assertEqual(__version__, self.example["tool_version"], REGENERATE)
        self.assertTrue(f">v{__version__}</span>" in self.example_html, REGENERATE)

    def test_example_results_match_a_fresh_demo_run(self):
        self.assertEqual(_outcomes(self.fresh), _outcomes(self.example), REGENERATE)
        self.assertEqual(_findings(self.fresh), _findings(self.example), REGENERATE)

    def test_example_statistics_and_demo_checks_match_a_fresh_demo_run(self):
        self.assertEqual(self.fresh["stats"], self.example["stats"], REGENERATE)
        self.assertEqual(self.fresh["demo"], self.example.get("demo"), REGENERATE)
        self.assertEqual(self.fresh["report_schema_version"], self.example["report_schema_version"])

    def test_example_html_shows_the_reasons_of_a_fresh_demo_run(self):
        for item in self.fresh["results"]:
            with self.subTest(endpoint=item["endpoint"], check=item["check"]):
                rendered = html.escape(item["reason"], quote=True)
                self.assertTrue(rendered in self.example_html, f"{rendered!r} missing; {REGENERATE}")


if __name__ == "__main__":
    unittest.main()
