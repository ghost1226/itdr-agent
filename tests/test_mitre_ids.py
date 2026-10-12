"""Terminal guard: the parent ID T1078 must not appear bare in source.

The project uses the cloud-accounts sub-technique T1078.004 everywhere. This
scans the package and scripts for a bare ``T1078`` (not followed by ``.``) so
stale comments or strings cannot creep back in.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

BARE_T1078 = re.compile(r"T1078(?!\.)")


def test_no_bare_t1078_in_package_or_scripts():
    offenders: list[str] = []
    for directory in ("itdr_agent", "scripts"):
        for path in sorted((PROJECT_ROOT / directory).glob("*.py")):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if BARE_T1078.search(line):
                    offenders.append(
                        f"{path.relative_to(PROJECT_ROOT)}:{lineno}: {line.strip()}"
                    )
    assert not offenders, (
        "Bare T1078 found (use T1078.004):\n" + "\n".join(offenders)
    )
