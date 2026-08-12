"""Shared pytest configuration for the core/ test suite.

The arm provisioner uses bounded wait-loops (IAM propagation, SSM registration,
the clean-start precondition gate). Those loops sleep between polls but bound
themselves on real ``time.monotonic`` deadlines. In tests we neutralize the
sleeps so the suite runs fast: happy-path provisions no longer pay the real
post-create IAM buffer, and timeout cases (which inject tiny deadlines) still
expire on real elapsed time — they just spin fast instead of sleeping.
"""
import time

import pytest


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Make time.sleep a no-op for every test so wait-loops run instantly.

    Safe because the whole core/ suite is deterministic (FakeAWS, no real I/O):
    nothing depends on real sleep duration for correctness, only on the
    monotonic deadlines, which are left intact.
    """
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
