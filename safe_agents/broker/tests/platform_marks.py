"""Skip marks for tests that depend on a host tool or a POSIX facility.

Each mark names the dependency in its reason, so a skipped test on a Windows
laptop or a slim container says what it needed instead of vanishing into a count.
Kept to the few dependencies the suite actually has; add one here rather than
writing a bare `sys.platform` check into a test module.
"""

from __future__ import annotations

import shutil
import sys

import pytest

IS_WINDOWS = sys.platform == "win32"

# The MCP transport tests find the child they spawned by its argv with `pgrep -f`,
# and assert it is reaped. That leak check is the point of those tests, so without
# pgrep they skip rather than run with it disabled. Windows is excluded even if a
# pgrep happens to be on PATH (Git for Windows' MSYS tools), because that one sees
# only MSYS processes and would report every native child as already gone.
requires_pgrep = pytest.mark.skipif(
    IS_WINDOWS or shutil.which("pgrep") is None,
    reason="needs `pgrep` (procps) to find and reap the spawned child by its argv; "
    "absent on Windows and on slim Linux images",
)

# `bash -n` syntax checks over deploy scripts that only ever run on a Linux box.
# On Windows, CreateProcess resolves a bare `bash` through System32 first, which
# is the WSL launcher when it resolves at all.
requires_posix_bash = pytest.mark.skipif(
    IS_WINDOWS or shutil.which("bash") is None,
    reason="runs `bash -n` over a POSIX deploy script; needs a POSIX bash",
)

# The runner-contract harness executes an agent's run.sh and notify.sh directly,
# as a Linux container runtime would. Windows has no exec for a shell script, so
# run_harness refuses there (UnsupportedHostError) instead of reporting eight
# contract violations that are really one missing host facility.
requires_posix_exec = pytest.mark.skipif(
    IS_WINDOWS,
    reason="executes a POSIX shell script directly (the runner-contract harness "
    "runs run.sh and notify.sh); Windows cannot",
)
