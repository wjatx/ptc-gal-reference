"""A minimal stdio MCP client for driving the gateway as a child process.

    with GatewayClient() as gateway:
        gateway.initialize()
        tools = gateway.list_tools()
        result = gateway.call_tool("payments__transfer", {"amount": "1000"})

Raw JSON-RPC lines rather than the `mcp` SDK's client, so the frames on the wire are
the ones any MCP client sends, and so this runs with nothing but the standard
library. Two callers share it: the subprocess test (`tests/test_gateway_subprocess.py`),
which is the check that runs on Windows, and the laptop demo (`demo.py`), which is
what a tester runs instead of hand-writing JSON-RPC. A shell pipe of `printf` lines
does not work in PowerShell, which is why the demo is Python.

Every wait is bounded. A blocking `readline()` on a pipe cannot time out portably
(`select()` does not work on pipes on Windows), so stdout is drained by a thread into
a queue. stderr is drained by a second thread for a different reason: a child that
writes enough diagnostics to fill the pipe would otherwise block forever on a write
nobody reads.

This module decides nothing. It carries frames and reports what came back.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from typing import Any

# A cold interpreter importing pydantic, the SDK and the broker takes a few seconds
# on a slow machine. Generous, because a timeout here reads as a hang, not a bug.
DEFAULT_TIMEOUT_SECONDS = 60.0

# The protocol revision this client offers. The server answers with the revision it
# will speak; this client uses only initialize, tools/list and tools/call, which every
# revision carries in the same shape.
PROTOCOL_VERSION = "2025-06-18"

GATEWAY_MODULE = "safe_agents.broker.gateway"

# Every variable the gateway reads its configuration from. A caller that wants the
# checked-in defaults, whatever the calling shell has exported, strips these.
BROKER_ENV_VARS = (
    "BROKER_STORE",
    "BROKER_MANIFEST",
    "BROKER_SECRETS",
    "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE",
    "BROKER_AUDIT_PATH",
    "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD",
    "BROKER_GRANT_LOAD",
    "BROKER_SQLITE_PATH",
)

_EOF = object()


class GatewayClientError(RuntimeError):
    """The gateway did not answer as an MCP server should.

    Carries the child's stderr so the message says why, which is almost always a
    refusal to boot printed there (an unrecognized secrets arm, a missing manifest).
    """

    def __init__(self, message: str, stderr: str = "") -> None:
        detail = f"{message}\n--- gateway stderr ---\n{stderr.rstrip()}" if stderr.strip() else message
        super().__init__(detail)
        self.stderr = stderr


def env_without_broker_config(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """`base` (default: this process's environment) minus every BROKER_* variable the
    gateway reads, so the child comes up on the checked-in example configuration."""
    source = os.environ if base is None else base
    return {k: v for k, v in source.items() if k not in BROKER_ENV_VARS}


class GatewayClient:
    """One gateway child process and the JSON-RPC conversation with it."""

    def __init__(
        self,
        command: Sequence[str] | None = None,
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.command = list(command) if command else [sys.executable, "-m", GATEWAY_MODULE]
        self.timeout = timeout
        self.proc = subprocess.Popen(
            self.command,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._next_id = 1
        self._frames: queue.Queue[Any] = queue.Queue()
        self.stdout_lines: list[bytes] = []
        self._stderr_chunks: list[bytes] = []
        self._stdout_reader = threading.Thread(target=self._drain_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_reader.start()
        self._stderr_reader.start()

    # -- context manager ---------------------------------------------------------

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- plumbing ----------------------------------------------------------------

    def _drain_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.stdout_lines.append(line)
            self._frames.put(line)
        self._frames.put(_EOF)

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        for chunk in iter(lambda: self.proc.stderr.read1(4096), b""):  # type: ignore[union-attr]
            self._stderr_chunks.append(chunk)

    @property
    def stderr_text(self) -> str:
        """Everything the child has written to stderr so far. Complete after close()."""
        return b"".join(self._stderr_chunks).decode("utf-8", "replace")

    def _send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self.close()
            raise GatewayClientError(
                f"the gateway closed its input before {message.get('method')!r} was sent "
                f"({type(exc).__name__}); it most likely refused to start",
                self.stderr_text,
            ) from None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no reply)."""
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a request and return its `result`, skipping notifications and other ids.

        Raises GatewayClientError on a JSON-RPC error, a non-JSON line on stdout (the
        protocol owns stdout, so that is a defect), the child exiting, or a timeout.
        """
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        while True:
            try:
                line = self._frames.get(timeout=self.timeout)
            except queue.Empty:
                self.close()
                raise GatewayClientError(
                    f"no reply to {method!r} within {self.timeout:g}s", self.stderr_text
                ) from None
            if line is _EOF:
                self.close()
                raise GatewayClientError(
                    f"the gateway exited (code {self.proc.returncode}) before replying to {method!r}",
                    self.stderr_text,
                )
            try:
                frame = json.loads(line.decode("utf-8"))
            except ValueError:
                raise GatewayClientError(
                    f"non-JSON line on the protocol's stdout: {line!r}", self.stderr_text
                ) from None
            if frame.get("id") != request_id:
                continue
            if "error" in frame:
                raise GatewayClientError(f"{method!r} returned a JSON-RPC error: {frame['error']}")
            return frame["result"]

    # -- the three calls an MCP client makes --------------------------------------

    def initialize(self, client_name: str = "safe-agents-stdio-client") -> dict[str, Any]:
        """The handshake: initialize, then the initialized notification."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "0"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.request("tools/list")["tools"])

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """The raw `tools/call` result: `content` blocks plus `isError`."""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    # -- shutdown ------------------------------------------------------------------

    def close(self) -> None:
        """Close stdin, which is how a stdio MCP server is told to exit, then reap it."""
        if self.proc.stdin and not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self._stdout_reader.join(timeout=self.timeout)
        self._stderr_reader.join(timeout=self.timeout)
        for pipe, reader in (
            (self.proc.stdout, self._stdout_reader),
            (self.proc.stderr, self._stderr_reader),
        ):
            if pipe is not None and not reader.is_alive():
                pipe.close()


def result_text(result: dict[str, Any]) -> str:
    """The text blocks of a `tools/call` result, joined."""
    return "\n".join(
        block.get("text", "") for block in result.get("content", []) if block.get("type") == "text"
    )
