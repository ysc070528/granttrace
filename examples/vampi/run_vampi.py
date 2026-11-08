"""Run a VAmPI checkout on 127.0.0.1 only, without the Flask debugger.

Usage: python run_vampi.py <vampi-checkout> <port> <vulnerable: 0|1>

VAmPI's own app.py listens on every interface with the debugger enabled. Run
this with the Python environment that has VAmPI's requirements installed, and
give each mode its own checkout: VAmPI keeps its SQLite database inside it.
See docs/case-studies/vampi.md.
"""
import os
import sys

if len(sys.argv) != 4 or sys.argv[3] not in {"0", "1"}:
    raise SystemExit(__doc__)
src, port, vulnerable = sys.argv[1], int(sys.argv[2]), sys.argv[3]
os.environ["vulnerable"] = vulnerable
os.environ["tokentimetolive"] = "3600"  # VAmPI's default of 60 s expires mid-scan
sys.path.insert(0, src)

from config import vuln_app  # noqa: E402

vuln_app.run(host="127.0.0.1", port=port, debug=False)
