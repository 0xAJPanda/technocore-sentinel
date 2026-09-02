"""Executable specifications for the versioned agent JSON contract."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from typing import Any, IO
import unittest
from unittest import mock

import technocore_sentinel
from technocore_sentinel.contract import SCHEMA_VERSION, agent_contract
from technocore_sentinel.scanner import ScanCategory, Severity


REPORT_FIELDS = {
    "schema_version",
    "room",
    "previous_seq",
    "first_seq",
    "last_seq",
    "next_seq",
    "new_message_count",
    "server_signed_count",
    "unsigned_count",
    "severity_counts",
    "category_counts",
    "findings",
    "coverage_gap",
    "missing_sequence_count",
    "baseline_only",
    "minimum_severity",
    "cursor_status",
    "cursor_recovered",
    "recovered_from_seq",
}
FINDING_FIELDS = {"seq", "from", "category", "severity", "rule", "excerpt"}
SUMMARY_FIELDS = {
    "schema_version", "room", "cursor_status", "new_message_count",
    "minimum_severity", "severity_counts", "category_counts", "coverage_gap",
    "missing_sequence_count", "baseline_only", "cursor_recovered", "review_required",
}
MONITOR_CONTRACT_FIXTURE = (
    Path(__file__).parent / "fixtures" / "compatibility" / "monitor_contract.json"
)
BASELINE_COMMIT = "bf7e90bd42e66ad4b03d6c3e5e7e28ecf1890684"
BASELINE_ARCHIVE_BYTE_LIMIT = 2 * 1024 * 1024
CHILD_STDOUT_LIMIT = 8192
CHILD_STDERR_LIMIT = 64 * 1024
SUBPROCESS_TIMEOUT = 30.0
_PIPE_CHUNK_SIZE = 64 * 1024
_TERMINATION_DRAIN_TIMEOUT = 2.0


def _run_bounded_subprocess(
    command: list[str],
    *,
    label: str,
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a child while concurrently enforcing hard pipe and time bounds."""

    if min(stdout_limit, stderr_limit) < 0 or timeout <= 0:
        raise ValueError("subprocess bounds must be positive")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )

    def kill_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    readers: list[threading.Thread] = []
    streams: dict[str, tuple[IO[Any], int, bytearray]] = {}
    overflow = threading.Event()
    reader_failed = threading.Event()
    overflow_names: list[str] = []
    try:
        if process.stdout is None or process.stderr is None:
            raise AssertionError(f"{label} pipes were not created")
        streams = {
            "stdout": (process.stdout, stdout_limit, bytearray()),
            "stderr": (process.stderr, stderr_limit, bytearray()),
        }

        def drain(name: str) -> None:
            pipe, limit, captured = streams[name]
            over_limit = False
            try:
                while True:
                    chunk = pipe.read(_PIPE_CHUNK_SIZE)
                    if not chunk:
                        return
                    if over_limit:
                        continue
                    remaining = limit - len(captured)
                    if len(chunk) > remaining:
                        if remaining > 0:
                            captured.extend(chunk[:remaining])
                        overflow_names.append(name)
                        overflow.set()
                        over_limit = True
                        continue
                    captured.extend(chunk)
            except (OSError, ValueError):
                reader_failed.set()

        readers = [
            threading.Thread(target=drain, args=(name,), daemon=True, name=f"bounded-{name}")
            for name in streams
        ]
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + timeout
        failure: str | None = None
        while process.poll() is None:
            if overflow.wait(timeout=min(0.01, max(0.0, deadline - time.monotonic()))):
                failure = f"{label} {overflow_names[0]} exceeded byte limit"
                break
            if reader_failed.is_set():
                failure = f"{label} pipes could not be read"
                break
            if time.monotonic() >= deadline:
                failure = f"{label} exceeded {timeout:g}-second timeout"
                break

        if failure is not None:
            kill_process_group()
        drain_deadline = min(deadline, time.monotonic() + _TERMINATION_DRAIN_TIMEOUT)
        try:
            process.wait(timeout=max(0.001, drain_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            kill_process_group()
            try:
                process.wait(timeout=_TERMINATION_DRAIN_TIMEOUT)
            except subprocess.TimeoutExpired as error:
                raise AssertionError(f"{label} could not be terminated within drain bound") from error
            if failure is None:
                failure = f"{label} exceeded {timeout:g}-second timeout"

        for reader in readers:
            reader.join(timeout=max(0.0, drain_deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            kill_process_group()
            for reader in readers:
                reader.join(timeout=_TERMINATION_DRAIN_TIMEOUT)
        if any(reader.is_alive() for reader in readers):
            for pipe, _, _ in streams.values():
                pipe.close()
            for reader in readers:
                reader.join(timeout=_TERMINATION_DRAIN_TIMEOUT)
            if any(reader.is_alive() for reader in readers):
                raise AssertionError(f"{label} pipes did not drain within bound")
            if failure is None:
                failure = f"{label} pipes did not drain within bound"

        if failure is None and overflow.is_set():
            failure = f"{label} {overflow_names[0]} exceeded byte limit"
        if failure is None and reader_failed.is_set():
            failure = f"{label} pipes could not be read"
        if failure is not None:
            raise AssertionError(failure)
        if process.returncode != 0:
            raise AssertionError(f"{label} exited with code {process.returncode}")
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            bytes(streams["stdout"][2]),
            bytes(streams["stderr"][2]),
        )
    except BaseException:
        kill_process_group()
        try:
            process.wait(timeout=_TERMINATION_DRAIN_TIMEOUT)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        for pipe, _, _ in streams.values():
            pipe.close()
        for reader in readers:
            reader.join(timeout=_TERMINATION_DRAIN_TIMEOUT)


def _write_baseline_archive(archive_bytes: bytes, parent: Path, name: str = "baseline.zip") -> Path:
    """Write one bounded archive through an exclusive descriptor below a fresh parent."""

    immutable_archive = bytes(archive_bytes)
    if len(immutable_archive) > BASELINE_ARCHIVE_BYTE_LIMIT:
        raise AssertionError("baseline zip archive exceeded byte limit")
    if (
        not name
        or name in {".", ".."}
        or os.sep in name
        or (os.altsep is not None and os.altsep in name)
    ):
        raise AssertionError("baseline zip archive name must be one safe basename")

    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    archive_fd: int | None = None
    try:
        archive_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(archive_fd, 0o600)
        view = memoryview(immutable_archive)
        while view:
            written = os.write(archive_fd, view)
            if written <= 0:
                raise AssertionError("baseline zip archive write made no progress")
            view = view[written:]
        os.fsync(archive_fd)
    finally:
        if archive_fd is not None:
            os.close(archive_fd)
        os.close(parent_fd)
    return parent / name


def _linux_pid_is_running(pid: int) -> bool:
    """Return whether a Linux PID exists and is not a dead zombie."""

    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


def _install_crypto_placeholders_source() -> str:
    """Return child code for inert import-only cryptography placeholders."""

    return r'''
import types
crypto = types.ModuleType("cryptography")
hazmat = types.ModuleType("cryptography.hazmat")
primitives = types.ModuleType("cryptography.hazmat.primitives")
serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")
asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
class _NeverUseCrypto:
    @classmethod
    def from_private_bytes(cls, value):
        raise AssertionError("contract must not use cryptography")
class _Raw:
    Raw = object()
serialization.Encoding = _Raw
serialization.PublicFormat = _Raw
ed25519.Ed25519PrivateKey = _NeverUseCrypto
crypto.hazmat = hazmat
hazmat.primitives = primitives
primitives.serialization = serialization
primitives.asymmetric = asymmetric
asymmetric.ed25519 = ed25519
for _module in (crypto, hazmat, primitives, serialization, asymmetric, ed25519):
    sys.modules[_module.__name__] = _module
'''


def _create_baseline_archive(repository: Path, parent: Path) -> Path:
    """Capture the pinned commit as one bounded zip file without extraction."""

    git = shutil.which("git")
    if git is None:
        raise AssertionError("git executable is required for provenance reconstruction")
    completed = _run_bounded_subprocess(
        [git, "-C", str(repository), "archive", "--format=zip", BASELINE_COMMIT],
        label="baseline git zip archive",
        env={},
        stdout_limit=BASELINE_ARCHIVE_BYTE_LIMIT,
        stderr_limit=CHILD_STDERR_LIMIT,
        timeout=SUBPROCESS_TIMEOUT,
    )
    return _write_baseline_archive(completed.stdout, parent)


def _run_baseline_contract(repository: Path, archive: Path, empty_cwd: Path) -> bytes:
    """Import and run the pinned CLI directly from the bounded zip archive."""

    source = r'''
import base64
import io
import os
from pathlib import Path
import sys
archive = Path(sys.argv[1]).resolve()
current_src = str((Path(sys.argv[2]).resolve() / "src"))
archive_src = f"{archive}{os.sep}src"
archive_prefix = f"{archive_src}{os.sep}"
current_prefix = f"{current_src}{os.sep}"
stdlib_paths = [entry for entry in sys.path if entry and Path(entry).is_absolute()]
sys.path[:] = [archive_src, *stdlib_paths]
if current_src in sys.path or any(entry.startswith(current_prefix) for entry in sys.path):
    raise AssertionError("current source tree present on baseline sys.path")
sys.dont_write_bytecode = True
''' + _install_crypto_placeholders_source() + r'''
from technocore_sentinel.cli import run
project_modules = [
    module for name, module in sys.modules.items()
    if name == "technocore_sentinel" or name.startswith("technocore_sentinel.")
]
for module in project_modules:
    location = getattr(module, "__file__", None)
    if not isinstance(location, str):
        raise AssertionError(f"project module lacks baseline zip path: {module.__name__}")
    absolute_location = os.path.abspath(location)
    if not absolute_location.startswith(archive_prefix):
        raise AssertionError(f"project import escaped baseline zip: {location}")
    if absolute_location.startswith(current_prefix):
        raise AssertionError(f"project import used current source tree: {location}")
output = io.StringIO()
def forbidden_client():
    raise AssertionError("contract must not construct a client")
result = run(["contract"], client_factory=forbidden_client, stdout=output)
payload = output.getvalue().encode("utf-8")
if result != 0 or len(payload) > 4096:
    raise AssertionError("invalid baseline contract result")
sys.stdout.write(base64.b64encode(payload).decode("ascii"))
'''
    completed = _run_bounded_subprocess(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-c",
            source,
            str(archive),
            str(repository),
        ],
        label="baseline contract child",
        cwd=empty_cwd,
        env={},
        stdout_limit=CHILD_STDOUT_LIMIT,
        stderr_limit=CHILD_STDERR_LIMIT,
        timeout=SUBPROCESS_TIMEOUT,
    )
    return base64.b64decode(completed.stdout, validate=True)


def _run_isolated_current_contract(repository: Path, empty_cwd: Path) -> bytes:
    """Run the current command with import/runtime side effects denied."""

    source = r'''
import base64
import builtins
import http.client
import io
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import urllib.request
root = Path(sys.argv[1]).resolve()
src = (root / "src").resolve()
stdlib_paths = [entry for entry in sys.path if entry and Path(entry).is_absolute()]
sys.path[:] = [str(root), str(src), *stdlib_paths]
sys.dont_write_bytecode = True
phase = "import"
allowed_read_roots = tuple(
    Path(entry).resolve() for entry in [str(root), str(src), *stdlib_paths]
    if Path(entry).exists()
)
write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_EXCL
filesystem_events = {
    "open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.rmdir",
    "os.mkdir", "os.link", "os.symlink", "os.chmod", "os.chown", "os.truncate",
    "os.utime", "os.walk", "os.chdir", "os.fchdir", "shutil.copyfile", "shutil.copytree",
}
def audit(event, args):
    if event.startswith("socket.") or event.startswith("subprocess.") or event in {
        "os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn",
    }:
        raise AssertionError(f"forbidden audited side effect: {event}")
    if event == "open":
        path, mode, flags = args
        if (isinstance(mode, str) and any(letter in mode for letter in "wax+")) or (
            isinstance(flags, int) and flags & write_flags
        ):
            raise AssertionError("filesystem write forbidden during import and runtime")
        if phase == "runtime":
            raise AssertionError("runtime filesystem open forbidden")
        if not isinstance(path, (str, bytes, os.PathLike)):
            raise AssertionError("non-path import open forbidden")
        resolved = Path(os.fsdecode(path)).resolve()
        if not any(resolved == base or base in resolved.parents for base in allowed_read_roots):
            raise AssertionError(f"import read outside explicit roots: {resolved}")
    elif event in filesystem_events and phase == "runtime":
        raise AssertionError(f"runtime filesystem event forbidden: {event}")
sys.addaudithook(audit)
''' + _install_crypto_placeholders_source() + r'''
import argparse
import shutil
import technocore_sentinel.cli as cli
import technocore_sentinel.client as client
import technocore_sentinel.identity as identity
project_modules = [
    module for name, module in sys.modules.items()
    if name == "technocore_sentinel" or name.startswith("technocore_sentinel.")
]
for module in project_modules:
    location = getattr(module, "__file__", None)
    if location is not None and src not in Path(location).resolve().parents:
        raise AssertionError(f"project import escaped current source: {location}")
phase = "runtime"
# Keep argparse's presentation deterministic without allowing its gettext
# wrapper to consult locale environment variables during command execution.
argparse._ = lambda message: message
argparse.ngettext = lambda singular, plural, count: singular if count == 1 else plural
shutil.get_terminal_size = lambda fallback=(80, 24): os.terminal_size(fallback)
def forbidden(route):
    def reject(*args, **kwargs):
        raise AssertionError(f"forbidden runtime route: {route}")
    return reject
class ForbiddenEnvironment(dict):
    def _reject(self, *args, **kwargs):
        raise AssertionError("runtime environment access forbidden")
    __getitem__ = get = __contains__ = __iter__ = __len__ = keys = items = values = _reject
    __setitem__ = __delitem__ = pop = popitem = setdefault = update = copy = _reject
os.environ = ForbiddenEnvironment()
os.getenv = forbidden("os.getenv")
for name in ("open", "stat", "lstat", "fstat", "access", "listdir", "scandir", "readlink",
             "mkdir", "makedirs", "remove", "unlink", "rename", "replace", "rmdir", "removedirs",
             "chmod", "fchmod", "chown", "fchown", "truncate", "ftruncate", "utime", "read", "write"):
    if hasattr(os, name):
        setattr(os, name, forbidden(f"os.{name}"))
builtins.open = forbidden("builtins.open")
io.open = forbidden("io.open")
for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
             "gethostbyaddr", "socketpair", "fromfd"):
    if hasattr(socket, name):
        setattr(socket, name, forbidden(f"socket.{name}"))
for connection in (http.client.HTTPConnection, http.client.HTTPSConnection):
    connection.connect = forbidden(f"{connection.__name__}.connect")
    connection.request = forbidden(f"{connection.__name__}.request")
for name in ("create_default_context", "wrap_socket"):
    if hasattr(ssl, name):
        setattr(ssl, name, forbidden(f"ssl.{name}"))
for name in ("urlopen", "build_opener", "install_opener", "urlretrieve"):
    if hasattr(urllib.request, name):
        setattr(urllib.request, name, forbidden(f"urllib.request.{name}"))
urllib.request.OpenerDirector.open = forbidden("urllib.request.OpenerDirector.open")
for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
    if hasattr(subprocess, name):
        setattr(subprocess, name, forbidden(f"subprocess.{name}"))
for name in ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp"):
    if hasattr(os, name):
        setattr(os, name, forbidden(f"os.{name}"))
for name in tuple(name for name in dir(os) if name.startswith(("spawn", "exec"))):
    setattr(os, name, forbidden(f"os.{name}"))
for name in ("TechnocoreClient", "load_identity", "create_identity", "derive_did_key", "sign_message",
             "next_nonce", "profile_location", "_load_nonce", "_locked_state", "_locked_monitor_state",
             "_read_json_at", "_write_json_at", "_commit_state", "_recover_state"):
    if hasattr(cli, name):
        setattr(cli, name, forbidden(f"cli.{name}"))
for name in ("create_identity", "load_identity", "derive_did_key", "sign_message", "sign_canonical",
             "next_nonce", "profile_location", "_open_parent"):
    if hasattr(identity, name):
        setattr(identity, name, forbidden(f"identity.{name}"))
for module, names in (
    (cli.secrets, ("token_bytes", "token_hex")),
    (identity.secrets, ("token_bytes", "token_hex")),
    (identity.time, ("time", "time_ns", "monotonic")),
):
    for name in names:
        if hasattr(module, name):
            setattr(module, name, forbidden(f"runtime state {module.__name__}.{name}"))
client.TechnocoreClient = forbidden("client.TechnocoreClient")
client.build_opener = forbidden("client.build_opener")
output = io.StringIO()
result = cli.run(["contract"], client_factory=forbidden("client factory"), stdout=output)
payload = output.getvalue().encode("utf-8")
if result != 0 or len(payload) > 4096:
    raise AssertionError("invalid isolated contract result")
sys.stdout.write(base64.b64encode(payload).decode("ascii"))
'''
    completed = _run_bounded_subprocess(
        [str(Path(sys.executable).resolve()), "-I", "-S", "-c", source, str(repository)],
        label="isolated current contract child",
        cwd=empty_cwd,
        env={},
        stdout_limit=CHILD_STDOUT_LIMIT,
        stderr_limit=CHILD_STDERR_LIMIT,
        timeout=SUBPROCESS_TIMEOUT,
    )
    return base64.b64decode(completed.stdout, validate=True)


class ContractTests(unittest.TestCase):
    def _assert_provenance_resource_guards(self, temporary_root: Path) -> None:
        executable = str(Path(sys.executable).resolve())
        cases = (
            ("stdout", "import sys; sys.stdout.buffer.write(b'x' * 9)", "stdout"),
            ("stderr", "import sys; sys.stderr.buffer.write(b'x' * 9)", "stderr"),
        )
        for label, source, expected in cases:
            with self.subTest(resource=label):
                with self.assertRaisesRegex(AssertionError, rf"guard {expected} exceeded byte limit"):
                    _run_bounded_subprocess(
                        [executable, "-I", "-S", "-c", source],
                        label="guard",
                        stdout_limit=8,
                        stderr_limit=8,
                        timeout=2.0,
                        env={},
                    )
        with self.assertRaisesRegex(AssertionError, "guard exceeded 0.05-second timeout"):
            _run_bounded_subprocess(
                [executable, "-I", "-S", "-c", "import time; time.sleep(5)"],
                label="guard",
                stdout_limit=8,
                stderr_limit=8,
                timeout=0.05,
                env={},
            )

        process_tree_source = r'''
import json
import os
from pathlib import Path
import subprocess
import sys
import time
grandchild = subprocess.Popen(
    [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"]
)
Path(sys.argv[1]).write_text(
    json.dumps({"child": os.getpid(), "grandchild": grandchild.pid}), encoding="ascii"
)
if sys.argv[2] == "overflow":
    sys.stdout.buffer.write(b"x" * 9)
    sys.stdout.buffer.flush()
time.sleep(30)
'''
        for mode, expected, run_timeout in (
            ("timeout", "guard exceeded 0.1-second timeout", 0.1),
            ("overflow", "guard stdout exceeded byte limit", 2.0),
        ):
            with self.subTest(process_tree=mode):
                pid_file = temporary_root / f"{mode}-pids.json"
                started = time.monotonic()
                with self.assertRaisesRegex(AssertionError, expected):
                    _run_bounded_subprocess(
                        [executable, "-I", "-S", "-c", process_tree_source, str(pid_file), mode],
                        label="guard",
                        stdout_limit=8,
                        stderr_limit=8,
                        timeout=run_timeout,
                        env={},
                    )
                self.assertLess(time.monotonic() - started, run_timeout + _TERMINATION_DRAIN_TIMEOUT)
                pids = json.loads(pid_file.read_text(encoding="ascii"))
                poll_deadline = time.monotonic() + _TERMINATION_DRAIN_TIMEOUT
                while any(_linux_pid_is_running(pid) for pid in pids.values()) and time.monotonic() < poll_deadline:
                    time.sleep(0.01)
                self.assertFalse(_linux_pid_is_running(pids["child"]), "direct child survived cleanup")
                self.assertFalse(_linux_pid_is_running(pids["grandchild"]), "grandchild survived cleanup")

        malformed_parent = temporary_root / "malformed-zip"
        malformed_parent.mkdir(mode=0o700)
        malformed_archive = _write_baseline_archive(b"not a zip", malformed_parent)
        archive_stat = malformed_archive.lstat()
        self.assertEqual(archive_stat.st_mode & 0o777, 0o600)
        self.assertEqual(archive_stat.st_mode & 0o170000, 0o100000)
        self.assertEqual(archive_stat.st_nlink, 1)
        malformed_cwd = malformed_parent / "empty-cwd"
        malformed_cwd.mkdir(mode=0o700)
        started = time.monotonic()
        with self.assertRaisesRegex(AssertionError, "baseline contract child exited with code"):
            _run_baseline_contract(
                Path(__file__).parents[1].resolve(),
                malformed_archive,
                malformed_cwd,
            )
        self.assertLess(time.monotonic() - started, SUBPROCESS_TIMEOUT)
        self.assertEqual(list(malformed_cwd.iterdir()), [])
        self.assertFalse(
            any(thread.name.startswith("bounded-") for thread in threading.enumerate()),
            "bounded subprocess reader thread leaked",
        )

    def test_monitor_contract_fixture_byte_stable(self) -> None:
        repository = Path(__file__).parents[1].resolve()
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            self._assert_provenance_resource_guards(temporary_root)
            empty_cwd = temporary_root / "empty-cwd"
            empty_cwd.mkdir(mode=0o700)
            archive = _create_baseline_archive(repository, temporary_root)
            archive_stat = archive.lstat()
            self.assertEqual(archive_stat.st_mode & 0o777, 0o600)
            self.assertEqual(archive_stat.st_mode & 0o170000, 0o100000)
            self.assertEqual(archive_stat.st_nlink, 1)
            baseline = _run_baseline_contract(repository, archive, empty_cwd)
            actual = _run_isolated_current_contract(repository, empty_cwd)
            self.assertEqual(list(empty_cwd.iterdir()), [])

        fixture = MONITOR_CONTRACT_FIXTURE.read_bytes()
        self.assertEqual(baseline, fixture)
        self.assertEqual(baseline, actual)
        self.assertEqual(len(fixture), 2758)
        self.assertEqual(
            hashlib.sha256(fixture).hexdigest(),
            "82b7802f2bc1db2405e2e8c83223fac6427903dea4cd97ce36ac7dea00ebcf0a",
        )
        parsed = json.loads(actual)
        self.assertEqual(
            actual,
            (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        self.assertEqual(
            set(parsed),
            {
                "content_trust",
                "max_reads_per_cycle",
                "max_records_per_response",
                "method",
                "name",
                "origin",
                "report_schema",
                "schema_version",
                "writes_exposed",
            },
        )
        self.assertIs(parsed["writes_exposed"], False)


class AgentContractTests(unittest.TestCase):
    def test_fixed_contract_is_deterministic_and_json_serializable(self) -> None:
        with (
            mock.patch("socket.socket", side_effect=AssertionError("network forbidden")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")),
        ):
            first = agent_contract()
            second = agent_contract()

        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(first, second)
        self.assertEqual(
            {key: first[key] for key in first if key not in {"report_schema", "summary_schema"}},
            {
                "schema_version": 1,
                "name": "technocore-sentinel-monitor-report",
                "display_name": "Technocore Room Safety Monitor",
                "integration_purpose": "content-free room safety and coverage gating",
                "commands": ["agent-check", "summarize-report"],
                "origin": "https://technocore.chat",
                "method": "GET",
                "max_reads_per_cycle": 2,
                "max_records_per_response": 200,
                "writes_exposed": False,
                "content_trust": "untrusted_sanitized_heuristics",
            },
        )
        self.assertEqual(json.loads(json.dumps(first, sort_keys=True)), first)

    def test_summary_schema_is_closed_complete_and_fresh(self) -> None:
        first = agent_contract()["summary_schema"]
        second = agent_contract()["summary_schema"]
        self.assertIsInstance(first, dict)
        self.assertIs(first["additionalProperties"], False)
        self.assertEqual(set(first["required"]), SUMMARY_FIELDS)
        self.assertEqual(set(first["properties"]), SUMMARY_FIELDS)
        self.assertEqual(first["properties"]["minimum_severity"]["enum"], ["low", "medium", "high"])
        self.assertEqual(first["properties"]["room"]["pattern"], "^[a-z0-9][a-z0-9_-]{0,47}$")
        self.assertEqual(first["properties"]["review_required"], {"type": "boolean"})
        first["required"].append("mutated")
        self.assertNotIn("mutated", second["required"])

    def test_report_schema_is_closed_complete_and_enumerated(self) -> None:
        schema = agent_contract()["report_schema"]
        self.assertIsInstance(schema, dict)
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), REPORT_FIELDS)
        self.assertEqual(set(schema["properties"]), REPORT_FIELDS)

        properties = schema["properties"]
        self.assertEqual(properties["schema_version"], {"type": "integer", "const": 1})
        self.assertEqual(properties["room"]["pattern"], "^[a-z0-9][a-z0-9_-]{0,47}$")
        self.assertEqual(
            properties["cursor_status"]["enum"],
            ["baseline", "advanced", "healthy_idle", "recovered_baseline"],
        )
        self.assertEqual(properties["minimum_severity"]["enum"], [severity.value for severity in Severity])
        self.assertEqual(
            properties["findings"]["items"]["properties"]["severity"]["enum"],
            [severity.value for severity in Severity],
        )
        categories = [category.value for category in ScanCategory]
        self.assertEqual(properties["findings"]["items"]["properties"]["category"]["enum"], categories)
        self.assertEqual(set(properties["category_counts"]["required"]), set(categories))

        finding = properties["findings"]["items"]
        self.assertIs(finding["additionalProperties"], False)
        self.assertEqual(set(finding["required"]), FINDING_FIELDS)
        self.assertEqual(set(finding["properties"]), FINDING_FIELDS)
        for field in ("first_seq", "last_seq", "recovered_from_seq"):
            self.assertEqual(properties[field]["type"], ["integer", "null"])

    def test_package_version_matches_project_version(self) -> None:
        project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(technocore_sentinel.__version__, project["project"]["version"])
        self.assertEqual(technocore_sentinel.__version__, "0.2.0")


if __name__ == "__main__":
    unittest.main()
