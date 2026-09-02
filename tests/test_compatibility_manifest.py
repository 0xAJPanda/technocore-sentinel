"""Tests for the frozen compatibility baseline manifest."""

from __future__ import annotations

import hashlib
import io
from collections import Counter
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import unicodedata


BASELINE_COMMIT = "bf7e90bd42e66ad4b03d6c3e5e7e28ecf1890684"
BASELINE_TREE = "61c5a6d07a2241b70da74b148b39ef3f66b58f82"
MANIFEST = Path(__file__).parents[1] / "docs/plans/2026-08-29-release-input-manifest.md"
IDS_BEGIN = "<!-- BEGIN BASELINE UNITTEST IDS -->"
IDS_END = "<!-- END BASELINE UNITTEST IDS -->"
RELEASE_CLASSES_BEGIN = "<!-- BEGIN RELEASE INPUT CLASSES -->"
RELEASE_CLASSES_END = "<!-- END RELEASE INPUT CLASSES -->"
RELEASE_CLASSES = frozenset(
    {
        "excluded-material",
        "historical-plan",
        "intended-release-input",
        "separately-reviewed-workflow",
    }
)
FROZEN_RELEASE_CLASS_COUNT = 45
FROZEN_RELEASE_CLASS_COUNTS = {
    "excluded-material": 1,
    "historical-plan": 1,
    "intended-release-input": 35,
    "separately-reviewed-workflow": 8,
}
FROZEN_RELEASE_CLASS_SHA256 = "b6d21eded5456e5dcd1b993064abf3f373f97936b50a38cf5bf37a47fd8b8bd4"
MONITOR_STATE_FIXTURES = (
    (
        "monitor_state_first.json",
        34,
        "7cde1efdcba4f41270f7f37317debf63bd1f41c2c5fc33d6d7393446c7cb0f8c",
    ),
    (
        "monitor_state_advanced.json",
        34,
        "c7c8c94f62600dc3105241547f217c35d468c2234f6145cffd50108433880dbe",
    ),
)
ID_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.])tests(?:\.[A-Za-z_][A-Za-z0-9_]*){3,}(?![A-Za-z0-9_.])"
)
PORCELAIN_ORDINARY_X = b" MTADRC"
PORCELAIN_ORDINARY_Y = b" MTD"
PORCELAIN_UNMERGED = frozenset({b"DD", b"AU", b"UD", b"UA", b"DU", b"AA", b"UU"})
PORCELAIN_SPECIAL = frozenset({b"??", b"!!"})
PORCELAIN_ALLOWED_XY = frozenset(
    {bytes((x, y)) for x in PORCELAIN_ORDINARY_X for y in PORCELAIN_ORDINARY_Y}
    - {b"  "}
) | PORCELAIN_UNMERGED | PORCELAIN_SPECIAL
PATH_SEPARATOR_CONFUSABLES = frozenset("\u2044\u2215\u29f5\u29f8\u29f9\ufe68\uff0f\uff3c")
GIT_STATUS_STDOUT_LIMIT = 1024 * 1024
GIT_STDERR_LIMIT = 4096
GIT_TIMEOUT_SECONDS = 5.0
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class _BoundedProcessError(RuntimeError):
    """A subprocess violated an output bound without echoing its output."""


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a start_new_session process tree and reap its leader promptly."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run without a shell while incrementally enforcing byte and time limits."""
    if stdout_limit < 0 or stderr_limit < 0 or timeout <= 0:
        raise ValueError("subprocess bounds must be non-negative and timeout must be positive")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=False,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    streams = {process.stdout: ("stdout", stdout_limit), process.stderr: ("stderr", stderr_limit)}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        for stream, stream_metadata in streams.items():
            selector.register(stream, selectors.EVENT_READ, stream_metadata)
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise TimeoutError(f"subprocess exceeded {timeout:g}-second timeout")
            events = selector.select(remaining_time)
            if not events:
                raise TimeoutError(f"subprocess exceeded {timeout:g}-second timeout")
            for key, _ in events:
                stream_name, limit = key.data
                remaining = limit - len(captured[stream_name])
                chunk = os.read(key.fd, min(65536, remaining + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(chunk) > remaining:
                    raise _BoundedProcessError(f"subprocess {stream_name} exceeded {limit}-byte limit")
                captured[stream_name].extend(chunk)
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise TimeoutError(f"subprocess exceeded {timeout:g}-second timeout")
        returncode = process.wait(timeout=remaining_time)
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(command, returncode, bytes(captured["stdout"]), bytes(captured["stderr"]))


def _write_new_regular_file(directory: Path, name: str, data: bytes, *, limit: int) -> os.stat_result:
    """Create one bounded mode-0600 file relative to an opened directory."""
    if not name or name in {".", ".."} or os.sep in name or (os.altsep and os.altsep in name):
        raise ValueError("file name must be one plain path component")
    if len(data) > limit:
        raise ValueError(f"file data exceeds {limit}-byte limit")
    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise ValueError("new file is not a singly linked mode-0600 regular file")
        view = memoryview(data)
        written_total = 0
        while view:
            written = os.write(descriptor, view[: limit - written_total])
            if written <= 0 or written > len(view):
                raise OSError("failed to write bounded file exactly")
            written_total += written
            view = view[written:]
        if written_total != len(data):
            raise OSError("bounded file write was incomplete")
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        if completed.st_size != len(data):
            raise OSError("bounded file size changed during write")
        return completed
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_descriptor)


def _git_status(repository: Path, git: Path) -> subprocess.CompletedProcess[bytes]:
    """Read status with repository/user config effects explicitly disabled."""
    command = [
        str(git),
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.preloadIndex=false",
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ]
    return _run_bounded(
        command,
        cwd=repository,
        env=dict(GIT_ENV),
        stdout_limit=GIT_STATUS_STDOUT_LIMIT,
        stderr_limit=GIT_STDERR_LIMIT,
        timeout=GIT_TIMEOUT_SECONDS,
    )


def _parse_manifest(manifest: str) -> tuple[list[str], int, str]:
    """Return strictly validated IDs, declared count, and declared digest."""
    if manifest.count(IDS_BEGIN) != 1:
        raise ValueError("manifest must contain exactly one BEGIN marker")
    if manifest.count(IDS_END) != 1:
        raise ValueError("manifest must contain exactly one END marker")

    begin = manifest.index(IDS_BEGIN)
    end = manifest.index(IDS_END)
    if begin >= end:
        raise ValueError("manifest markers are out of order")

    lines = manifest.splitlines()
    commit_line = f"- Baseline commit: `{BASELINE_COMMIT}`"
    commit_lines = [line for line in lines if "Baseline commit:" in line]
    if commit_lines != [commit_line]:
        raise ValueError("manifest must contain exactly one canonical baseline commit line")

    count_lines = [line for line in lines if "Baseline test count:" in line]
    if len(count_lines) != 1:
        raise ValueError("manifest must contain exactly one baseline count line")
    count_match = re.fullmatch(r"- Baseline test count: `([0-9]+)`", count_lines[0])
    if count_match is None:
        raise ValueError("baseline count line is malformed")
    declared_count = int(count_match.group(1))

    hash_lines = [line for line in lines if "ID block SHA-256:" in line]
    if len(hash_lines) != 1:
        raise ValueError("manifest must contain exactly one hash line")
    hash_match = re.fullmatch(r"- ID block SHA-256: `([0-9a-f]{64})`", hash_lines[0])
    if hash_match is None:
        raise ValueError("hash line must contain exactly 64 lowercase hexadecimal characters")
    declared_hash = hash_match.group(1)

    frozen_section = manifest[begin + len(IDS_BEGIN) : end]
    if not frozen_section.startswith("\n```text\n") or not frozen_section.endswith("\n```\n"):
        raise ValueError("ID block must be a canonical text fence")
    frozen_ids = frozen_section[len("\n```text\n") : -len("\n```\n")].splitlines()
    if not frozen_ids:
        raise ValueError("ID block must not be empty")
    malformed = [test_id for test_id in frozen_ids if ID_PATTERN.fullmatch(test_id) is None]
    if malformed:
        raise ValueError(f"ID block contains malformed or indented IDs: {malformed!r}")
    if len(frozen_ids) != len(set(frozen_ids)):
        raise ValueError("ID block contains duplicate IDs")
    if frozen_ids != sorted(frozen_ids):
        raise ValueError("ID block is not sorted")
    if declared_count != len(frozen_ids):
        raise ValueError("declared baseline count does not match the ID block")

    hash_domain = "".join(f"{test_id}\n" for test_id in frozen_ids).encode("utf-8")
    if hashlib.sha256(hash_domain).hexdigest() != declared_hash:
        raise ValueError("declared hash does not match the ID block")

    outside = manifest[:begin] + manifest[end + len(IDS_END) :]
    outside_ids = [match.group(0) for match in ID_PATTERN.finditer(outside)]
    if outside_ids:
        raise ValueError(f"manifest contains IDs outside the marked block: {outside_ids!r}")

    return frozen_ids, declared_count, declared_hash


def _validate_release_path(path: str) -> None:
    """Reject paths that cannot be exact repository-relative release inputs."""
    if unicodedata.normalize("NFC", path) != path:
        raise ValueError(f"release path is not NFC-normalized: {path!r}")
    if not path or path.startswith("/") or path.endswith("/") or "\\" in path:
        raise ValueError(f"release path is not canonical repository-relative POSIX: {path!r}")
    if any(component in {"", ".", ".."} for component in path.split("/")):
        raise ValueError(f"release path contains an empty or traversal component: {path!r}")
    if any(character in "*?[]" for character in path):
        raise ValueError(f"release path contains glob syntax: {path!r}")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in path
    ):
        raise ValueError(f"release path contains a forbidden Unicode category: {path!r}")
    if any(character in PATH_SEPARATOR_CONFUSABLES for character in path):
        raise ValueError(f"release path contains a separator confusable: {path!r}")


def _parse_release_classes(manifest: str) -> dict[str, str]:
    """Parse the canonical path-TAB-enum machine block."""
    if manifest.count(RELEASE_CLASSES_BEGIN) != 1:
        raise ValueError("manifest must contain exactly one release-class BEGIN marker")
    if manifest.count(RELEASE_CLASSES_END) != 1:
        raise ValueError("manifest must contain exactly one release-class END marker")
    begin = manifest.index(RELEASE_CLASSES_BEGIN)
    end = manifest.index(RELEASE_CLASSES_END)
    if begin >= end:
        raise ValueError("release-class markers are out of order")
    section = manifest[begin + len(RELEASE_CLASSES_BEGIN) : end]
    if not section.startswith("\n```text\n") or not section.endswith("\n```\n"):
        raise ValueError("release-class block must be a canonical text fence")
    lines = section[len("\n```text\n") : -len("\n```\n")].splitlines()
    if not lines:
        raise ValueError("release-class block must not be empty")

    classifications: dict[str, str] = {}
    for line in lines:
        if line.count("\t") != 1:
            raise ValueError(f"release-class line must be exact path-TAB-class: {line!r}")
        path, release_class = line.split("\t")
        _validate_release_path(path)
        if release_class not in RELEASE_CLASSES:
            raise ValueError(f"unknown release class: {release_class!r}")
        if path in classifications:
            raise ValueError(f"duplicate release path: {path!r}")
        classifications[path] = release_class
    if list(classifications) != sorted(classifications):
        raise ValueError("release-class block paths are not sorted")
    return classifications


def _release_class_snapshot_sha256(classifications: dict[str, str]) -> str:
    """Hash sorted exact path-TAB-class-LF records."""
    canonical = "".join(
        f"{path}\t{classifications[path]}\n" for path in sorted(classifications)
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_porcelain_v1_z(output: bytes) -> list[str]:
    """Return every path represented by bounded porcelain-v1 -z output."""
    if not output:
        return []
    if not output.endswith(b"\0"):
        raise ValueError("porcelain output is not NUL terminated")
    records = output[:-1].split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4 or record[2:3] != b" ":
            raise ValueError(f"malformed porcelain record: {record!r}")
        xy = record[:2]
        if xy not in PORCELAIN_ALLOWED_XY:
            raise ValueError(f"invalid porcelain status: {record[:2]!r}")
        try:
            paths.append(record[3:].decode("utf-8", errors="strict"))
        except UnicodeDecodeError as error:
            raise ValueError("porcelain path is not UTF-8") from error
        if record[0] in b"RC":
            if index >= len(records):
                raise ValueError("rename/copy porcelain record is missing its source path")
            if not records[index]:
                raise ValueError("rename/copy porcelain source path is empty")
            try:
                paths.append(records[index].decode("utf-8", errors="strict"))
            except UnicodeDecodeError as error:
                raise ValueError("porcelain source path is not UTF-8") from error
            index += 1
    return paths


class CompatibilityManifestTests(unittest.TestCase):
    def test_monitor_state_fixture_is_byte_stable(self) -> None:
        repository = Path(__file__).parents[1].resolve()
        fixture_root = repository / "tests/fixtures/compatibility"
        git_name = shutil.which("git")
        if git_name is None:
            self.fail("git executable is required for baseline monitor-state verification")
        git = Path(git_name).resolve()

        payloads = (
            {
                "room": "lobby",
                "count": 1,
                "first_seq": 3,
                "last_seq": 3,
                "messages": [{"seq": 3, "from": "alice", "text": "hello"}],
            },
            {
                "room": "lobby",
                "count": 1,
                "first_seq": 4,
                "last_seq": 4,
                "messages": [{"seq": 4, "from": "bob", "text": "next"}],
            },
        )

        class SyntheticReadOnlyClient:
            def __init__(self, response: dict[str, object]) -> None:
                self.response = response
                self.calls: list[tuple[str, int, int | None]] = []

            def get_room(
                self, room: str, *, limit: int, since: int | None = None
            ) -> dict[str, object]:
                self.calls.append((room, limit, since))
                return self.response

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            current_root = temporary_root / "current-state"
            current_state = current_root / "monitor.json"
            current_snapshots: list[bytes] = []
            current_reports: list[dict[str, object]] = []
            current_calls: list[list[tuple[str, int, int | None]]] = []

            from technocore_sentinel.cli import run

            with (
                mock.patch(
                    "technocore_sentinel.cli.create_identity",
                    side_effect=AssertionError("identity creation forbidden"),
                ),
                mock.patch(
                    "technocore_sentinel.cli.load_identity",
                    side_effect=AssertionError("identity loading forbidden"),
                ),
                mock.patch(
                    "technocore_sentinel.cli.sign_message",
                    side_effect=AssertionError("signing forbidden"),
                ),
            ):
                for payload in payloads:
                    client = SyntheticReadOnlyClient(payload)
                    output = io.StringIO()
                    self.assertEqual(
                        run(
                            [
                                "monitor",
                                "--room",
                                "lobby",
                                "--state-file",
                                str(current_state),
                                "--format",
                                "json",
                            ],
                            client_factory=lambda client=client: client,  # type: ignore[arg-type]
                            stdout=output,
                        ),
                        0,
                    )
                    current_snapshots.append(current_state.read_bytes())
                    current_reports.append(json.loads(output.getvalue()))
                    current_calls.append(client.calls)

                final_state_before_contract = current_state.read_bytes()
                contract_output = io.StringIO()
                contract_client = mock.Mock(side_effect=AssertionError("contract client forbidden"))
                self.assertEqual(run(["contract"], client_factory=contract_client, stdout=contract_output), 0)
                contract_client.assert_not_called()
                current_contract = contract_output.getvalue().encode("utf-8")
                self.assertEqual(current_state.read_bytes(), final_state_before_contract)

            archive = _run_bounded(
                [str(git), "archive", "--format=zip", BASELINE_COMMIT, "--", "src"],
                cwd=repository,
                env=dict(GIT_ENV),
                stdout_limit=512 * 1024,
                stderr_limit=GIT_STDERR_LIMIT,
                timeout=GIT_TIMEOUT_SECONDS,
            )
            self.assertEqual(
                archive.returncode,
                0,
                archive.stderr.decode("utf-8", errors="replace"),
            )
            archive_limit = 512 * 1024
            self.assertGreater(len(archive.stdout), 0)
            self.assertLessEqual(len(archive.stdout), archive_limit)
            archive_root = temporary_root / "baseline-archive"
            archive_root.mkdir(mode=0o700)
            archive_path = archive_root / "baseline.zip"
            archive_status = _write_new_regular_file(
                archive_root,
                archive_path.name,
                archive.stdout,
                limit=archive_limit,
            )
            self.assertTrue(stat.S_ISREG(archive_status.st_mode))
            self.assertEqual(stat.S_IMODE(archive_status.st_mode), 0o600)
            self.assertEqual(archive_status.st_nlink, 1)
            self.assertEqual(archive_status.st_size, len(archive.stdout))
            archive_sha256 = hashlib.sha256(archive.stdout).hexdigest()

            baseline_state = temporary_root / "baseline-state/monitor.json"
            baseline_cwd = temporary_root / "baseline-cwd"
            baseline_cwd.mkdir(mode=0o700)
            self.assertEqual(list(baseline_cwd.iterdir()), [])
            baseline_program = """
import hashlib
import json
from io import StringIO
import os
from pathlib import Path
import stat
import sys
import types

archive = Path(sys.argv[1])
state = Path(sys.argv[2])
payloads = json.loads(sys.argv[3])
repository_src = str(Path(sys.argv[4]) / "src")
expected_archive_hash = sys.argv[5]
if list(Path.cwd().iterdir()):
    raise RuntimeError("baseline working directory is not empty")

archive_status = archive.stat(follow_symlinks=False)
if not stat.S_ISREG(archive_status.st_mode):
    raise RuntimeError("baseline archive is not a regular file")
if stat.S_IMODE(archive_status.st_mode) != 0o600 or archive_status.st_nlink != 1:
    raise RuntimeError("baseline archive metadata changed")
with archive.open("rb") as archive_file:
    archive_hash = hashlib.file_digest(archive_file, "sha256").hexdigest()
if archive_hash != expected_archive_hash:
    raise RuntimeError("baseline archive hash changed")

stdlib_paths = tuple(sys.path)
if any(not path or "site-packages" in path or "dist-packages" in path for path in stdlib_paths):
    raise RuntimeError(f"non-stdlib isolated path present: {stdlib_paths!r}")
archive_src = str(archive) + "/src"
sys.path[:] = [archive_src, *stdlib_paths]
if repository_src in sys.path or str(Path.cwd()) in sys.path:
    raise RuntimeError("current repository or working directory leaked onto sys.path")

def forbidden(*args, **kwargs):
    raise AssertionError("cryptography/identity/signing/network/write operation forbidden")

# The monitor baseline needs identity's import-time names, never crypto operations.
cryptography = types.ModuleType("cryptography")
hazmat = types.ModuleType("cryptography.hazmat")
primitives = types.ModuleType("cryptography.hazmat.primitives")
serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")
asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
for package in (cryptography, hazmat, primitives, asymmetric):
    package.__path__ = []
serialization.__getattr__ = forbidden
ed25519.Ed25519PrivateKey = type(
    "Ed25519PrivateKey",
    (),
    {"from_private_bytes": staticmethod(forbidden)},
)
primitives.serialization = serialization
asymmetric.ed25519 = ed25519
sys.modules.update({
    module.__name__: module
    for module in (cryptography, hazmat, primitives, serialization, asymmetric, ed25519)
})

import technocore_sentinel.cli as cli

archive_module_prefix = archive_src + "/technocore_sentinel/"
loaded_sources = {
    name: getattr(module, "__file__", None)
    for name, module in sys.modules.items()
    if name == "technocore_sentinel" or name.startswith("technocore_sentinel.")
}
if not loaded_sources or any(
    not isinstance(source, str) or not source.startswith(archive_module_prefix)
    for source in loaded_sources.values()
):
    raise RuntimeError(f"baseline module provenance mismatch: {loaded_sources!r}")
if any(repository_src in source for source in loaded_sources.values() if isinstance(source, str)):
    raise RuntimeError("current repository source was imported")

cli.create_identity = forbidden
cli.load_identity = forbidden
cli.sign_message = forbidden
cli.TechnocoreClient._request = forbidden
cli.TechnocoreClient.publish_profile = forbidden
cli.TechnocoreClient.post_signed_message = forbidden

snapshots = []
reports = []
calls = []

class Client:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get_room(self, room, *, limit, since=None):
        self.calls.append([room, limit, since])
        return self.response

for payload in payloads:
    client = Client(payload)
    output = StringIO()
    result = cli.run(
        ["monitor", "--room", "lobby", "--state-file", str(state), "--format", "json"],
        client_factory=lambda client=client: client,
        stdout=output,
    )
    if result != 0:
        raise SystemExit(result)
    snapshots.append(state.read_bytes().hex())
    reports.append(json.loads(output.getvalue()))
    calls.append(client.calls)

print(json.dumps({
    "snapshots": snapshots,
    "reports": reports,
    "calls": calls,
    "parent_mode": stat.S_IMODE(state.parent.stat().st_mode),
    "state_mode": stat.S_IMODE(state.stat().st_mode),
    "lock_mode": stat.S_IMODE((state.parent / ".monitor.lock").stat().st_mode),
}, sort_keys=True, separators=(",", ":")))
"""
            baseline = _run_bounded(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-c",
                    baseline_program,
                    str(archive_path),
                    str(baseline_state),
                    json.dumps(payloads, sort_keys=True, separators=(",", ":")),
                    str(repository),
                    archive_sha256,
                ],
                cwd=baseline_cwd,
                env={},
                stdout_limit=64 * 1024,
                stderr_limit=GIT_STDERR_LIMIT,
                timeout=GIT_TIMEOUT_SECONDS,
            )
            self.assertEqual(
                baseline.returncode,
                0,
                baseline.stderr.decode("utf-8", errors="replace"),
            )
            baseline_result = json.loads(baseline.stdout)
            baseline_snapshots = [bytes.fromhex(value) for value in baseline_result["snapshots"]]

            fixtures = [fixture_root.joinpath(name).read_bytes() for name, _, _ in MONITOR_STATE_FIXTURES]
            self.assertEqual(current_snapshots, fixtures)
            self.assertEqual(baseline_snapshots, fixtures)
            for fixture, (name, expected_length, expected_sha256) in zip(
                fixtures, MONITOR_STATE_FIXTURES, strict=True
            ):
                with self.subTest(fixture=name):
                    self.assertEqual(len(fixture), expected_length)
                    self.assertEqual(hashlib.sha256(fixture).hexdigest(), expected_sha256)
                    self.assertTrue(fixture.endswith(b"\n"))
                    state_payload = json.loads(fixture)
                    self.assertEqual(set(state_payload), {"rooms", "version"})
                    self.assertIs(type(state_payload["version"]), int)
                    self.assertEqual(state_payload["version"], 1)
                    self.assertIs(type(state_payload["rooms"]), dict)
                    self.assertEqual(set(state_payload["rooms"]), {"lobby"})
                    self.assertIs(type(state_payload["rooms"]["lobby"]), int)

            self.assertEqual(current_calls, [[("lobby", 200, None)], [("lobby", 200, 3)]])
            self.assertEqual(
                baseline_result["calls"],
                [[['lobby', 200, None]], [['lobby', 200, 3]]],
            )
            self.assertEqual(baseline_result["reports"], current_reports)
            self.assertEqual(
                [(report["previous_seq"], report["next_seq"], report["cursor_status"]) for report in current_reports],
                [(0, 3, "baseline"), (3, 4, "advanced")],
            )
            self.assertEqual(
                [json.loads(fixture)["rooms"]["lobby"] for fixture in fixtures],
                [3, 4],
            )
            self.assertTrue(all("severity_counts" in report for report in current_reports))
            self.assertTrue(all("severity_counts" not in json.loads(fixture) for fixture in fixtures))
            self.assertEqual(
                current_contract,
                (fixture_root / "monitor_contract.json").read_bytes(),
            )
            self.assertTrue(all(current_contract != fixture for fixture in fixtures))
            self.assertTrue(all(current_contract != json.dumps(report).encode("utf-8") for report in current_reports))
            self.assertEqual(stat.S_IMODE(current_root.stat().st_mode), baseline_result["parent_mode"])
            self.assertEqual(stat.S_IMODE(current_state.stat().st_mode), baseline_result["state_mode"])
            self.assertEqual(
                stat.S_IMODE((current_root / ".monitor.lock").stat().st_mode),
                baseline_result["lock_mode"],
            )
            self.assertEqual(
                (baseline_result["parent_mode"], baseline_result["state_mode"], baseline_result["lock_mode"]),
                (0o700, 0o600, 0o600),
            )

    def test_every_dirty_path_has_one_release_class(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        classifications = _parse_release_classes(manifest)

        def assert_frozen_snapshot(candidate: dict[str, str]) -> None:
            self.assertEqual(len(candidate), FROZEN_RELEASE_CLASS_COUNT)
            self.assertEqual(Counter(candidate.values()), FROZEN_RELEASE_CLASS_COUNTS)
            self.assertEqual(_release_class_snapshot_sha256(candidate), FROZEN_RELEASE_CLASS_SHA256)

        # This snapshot is independent of the live dirty set, which can be empty in CI.
        assert_frozen_snapshot(classifications)

        deleted = dict(classifications)
        deleted.pop(next(iter(deleted)))
        reclassified = dict(classifications)
        reclassified_path = next(
            path
            for path, release_class in reclassified.items()
            if release_class == "intended-release-input"
        )
        reclassified[reclassified_path] = "historical-plan"
        for mutation, hostile_snapshot in {
            "deleted entry": deleted,
            "reclassified entry": reclassified,
        }.items():
            with self.subTest(snapshot_mutation=mutation):
                self.assertNotEqual(
                    _release_class_snapshot_sha256(hostile_snapshot), FROZEN_RELEASE_CLASS_SHA256
                )
                with self.assertRaises(AssertionError):
                    assert_frozen_snapshot(hostile_snapshot)

        sample_path = next(iter(classifications))
        sample_class = classifications[sample_path]
        sample_line = f"{sample_path}\t{sample_class}"
        hostile_manifests = {
            "duplicate BEGIN": manifest.replace(
                RELEASE_CLASSES_BEGIN, f"{RELEASE_CLASSES_BEGIN}\n{RELEASE_CLASSES_BEGIN}", 1
            ),
            "duplicate END": manifest.replace(
                RELEASE_CLASSES_END, f"{RELEASE_CLASSES_END}\n{RELEASE_CLASSES_END}", 1
            ),
            "duplicate path": manifest.replace(sample_line, f"{sample_line}\n{sample_line}", 1),
            "unknown class": manifest.replace(sample_line, f"{sample_path}\tnot-a-release-class", 1),
            "absolute path": manifest.replace(sample_line, f"/{sample_path}\t{sample_class}", 1),
            "traversal path": manifest.replace(sample_line, f"../{sample_path}\t{sample_class}", 1),
            "glob path": manifest.replace(sample_line, f"{sample_path}*\t{sample_class}", 1),
            "control path": manifest.replace(sample_line, f"bad\x01path\t{sample_class}", 1),
            "missing separator": manifest.replace(sample_line, f"{sample_path} {sample_class}", 1),
        }
        for mutation, hostile_manifest in hostile_manifests.items():
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    _parse_release_classes(hostile_manifest)

        _validate_release_path("ordinary path/with spaces.txt")
        unicode_hostile_paths = {
            "bidi override": "bad\u202epath",
            "zero width": "bad\u200bpath",
            "surrogate": "bad\ud800path",
            "private use": "bad\ue000path",
            "unassigned": "bad\u0378path",
            "decomposed NFD": "cafe\u0301.txt",
            "division slash": "bad\u2215path",
            "fraction slash": "bad\u2044path",
            "big solidus": "bad\u29f8path",
            "fullwidth slash": "bad\uff0fpath",
            "big reverse solidus": "bad\u29f9path",
            "fullwidth backslash": "bad\uff3cpath",
            "line separator": "bad\u2028path",
            "paragraph separator": "bad\u2029path",
        }
        for mutation, hostile_path in unicode_hostile_paths.items():
            with self.subTest(unicode_path=mutation):
                with self.assertRaises(ValueError):
                    _validate_release_path(hostile_path)

        synthetic = (
            b" M ordinary.txt\0"
            b"?? path with spaces.txt\0"
            b"R  renamed destination.txt\0renamed source.txt\0"
            b"C  copied\nline.txt\0copy source.txt\0"
        )
        self.assertEqual(
            _parse_porcelain_v1_z(synthetic),
            [
                "ordinary.txt",
                "path with spaces.txt",
                "renamed destination.txt",
                "renamed source.txt",
                "copied\nline.txt",
                "copy source.txt",
            ],
        )
        for xy in sorted(PORCELAIN_ALLOWED_XY):
            destination = xy + b" destination\0"
            expected = ["destination"]
            if xy[:1] in {b"R", b"C"}:
                destination += b"source\0"
                expected.append("source")
            with self.subTest(allowed_xy=xy):
                self.assertEqual(_parse_porcelain_v1_z(destination), expected)

        status_alphabet = b" MADRCU?!"
        disallowed_xy = {
            bytes((x, y))
            for x in status_alphabet
            for y in status_alphabet
            if bytes((x, y)) not in PORCELAIN_ALLOWED_XY
        }
        self.assertIn(b"?M", disallowed_xy)
        self.assertIn(b"!A", disallowed_xy)
        self.assertIn(b"RR", disallowed_xy)
        self.assertIn(b"MR", disallowed_xy)
        for xy in sorted(disallowed_xy):
            with self.subTest(disallowed_xy=xy):
                with self.assertRaises(ValueError):
                    _parse_porcelain_v1_z(xy + b" path\0")
        for hostile_output in (
            b" M missing-terminator",
            b"XX invalid-status\0",
            b"R  missing-source\0",
            b"R  empty-source\0\0",
            b"?? invalid-utf8-\xff\0",
        ):
            with self.subTest(hostile_output=hostile_output):
                with self.assertRaises(ValueError):
                    _parse_porcelain_v1_z(hostile_output)

        repository = Path(__file__).parents[1].resolve()
        git_name = shutil.which("git")
        if git_name is None:
            self.fail("git executable is required for dirty-path classification")
        git = Path(git_name).resolve()
        self.assertTrue(git.is_absolute(), f"discovered git path is not absolute: {git}")
        completed = _git_status(repository, git)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        dirty_paths = _parse_porcelain_v1_z(completed.stdout)
        self.assertEqual(len(dirty_paths), len(set(dirty_paths)), "git status repeated a dirty path")
        missing = sorted(set(dirty_paths).difference(classifications))
        self.assertEqual(missing, [], f"dirty paths missing an exact release class: {missing!r}")

    def test_git_status_execution_is_exact_and_bounded(self) -> None:
        repository = Path("/safe/repository")
        git = Path("/usr/bin/git")
        result = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch(f"{__name__}._run_bounded", return_value=result) as bounded:
            self.assertIs(_git_status(repository, git), result)
        bounded.assert_called_once_with(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.preloadIndex=false",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            cwd=repository,
            env={
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            },
            stdout_limit=1024 * 1024,
            stderr_limit=4096,
            timeout=5.0,
        )
        self.assertNotIn("HOME", GIT_ENV)

        git_name = shutil.which("git")
        if git_name is None:
            self.fail("git executable is required for fsmonitor isolation verification")
        real_git = Path(git_name).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            repository_path = Path(temporary)
            setup_prefix = [
                str(real_git),
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.preloadIndex=false",
            ]
            initialized = _run_bounded(
                [*setup_prefix, "init", "--quiet"],
                cwd=repository_path,
                env=dict(GIT_ENV),
                stdout_limit=4096,
                stderr_limit=4096,
                timeout=5.0,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr.decode(errors="replace"))
            marker = repository_path / "fsmonitor-was-run"
            fake_hook = repository_path / "fake-fsmonitor"
            fake_hook.write_text(f"#!/bin/sh\n: > {marker}\nexit 1\n", encoding="utf-8")
            fake_hook.chmod(0o700)
            configured = _run_bounded(
                [*setup_prefix, "config", "core.fsmonitor", str(fake_hook)],
                cwd=repository_path,
                env=dict(GIT_ENV),
                stdout_limit=4096,
                stderr_limit=4096,
                timeout=5.0,
            )
            self.assertEqual(configured.returncode, 0, configured.stderr.decode(errors="replace"))
            isolated_status = _git_status(repository_path, real_git)
            self.assertEqual(isolated_status.returncode, 0, isolated_status.stderr.decode(errors="replace"))
            self.assertFalse(marker.exists(), "repository fsmonitor command was executed")

        python = str(Path(sys.executable).resolve())
        for stream in ("stdout", "stderr"):
            descriptor = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"
            command = [python, "-I", "-c", f"import sys; {descriptor}.write(b'x' * 17)"]
            limits = {"stdout_limit": 16, "stderr_limit": 16}
            with self.subTest(cap_plus_one=stream):
                with self.assertRaisesRegex(_BoundedProcessError, rf"{stream} exceeded 16-byte limit"):
                    _run_bounded(
                        command,
                        cwd=Path(tempfile.gettempdir()),
                        env={},
                        timeout=5.0,
                        **limits,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            descendant_pid_file = temporary_path / "descendant.pid"
            descendant_program = (
                "import pathlib, subprocess, sys, time; "
                "child = subprocess.Popen([sys.executable, '-I', '-c', "
                "'import time; time.sleep(10)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii'); "
                "time.sleep(10)"
            )
            with self.assertRaisesRegex(TimeoutError, "subprocess exceeded"):
                _run_bounded(
                    [python, "-I", "-c", descendant_program, str(descendant_pid_file)],
                    cwd=temporary_path,
                    env={},
                    stdout_limit=16,
                    stderr_limit=16,
                    timeout=0.2,
                )
            descendant_pid = int(descendant_pid_file.read_text(encoding="ascii"))
            descendant_state = Path(f"/proc/{descendant_pid}/stat")
            if descendant_state.exists():
                # A killed orphan can remain briefly as a zombie until PID 1 reaps it.
                self.assertEqual(descendant_state.read_text(encoding="ascii").split()[2], "Z")

    def test_baseline_commit_is_exact(self) -> None:
        expected_commit = "bf7e90bd42e66ad4b03d6c3e5e7e28ecf1890684"
        expected_tree = "61c5a6d07a2241b70da74b148b39ef3f66b58f82"
        self.assertEqual(BASELINE_COMMIT, expected_commit)
        self.assertEqual(BASELINE_TREE, expected_tree)

        repository = Path(__file__).parents[1].resolve()
        git_name = shutil.which("git")
        if git_name is None:
            self.fail("git executable is required for baseline provenance verification")
        git = Path(git_name).resolve()
        self.assertTrue(git.is_absolute(), f"discovered git path is not absolute: {git}")
        self.assertRegex(BASELINE_COMMIT, r"\A[0-9a-f]{40}\Z")
        self.assertRegex(BASELINE_TREE, r"\A[0-9a-f]{40}\Z")

        def run_git(
            working_tree: Path,
            *arguments: str,
            expected_returncode: int = 0,
        ) -> subprocess.CompletedProcess[str]:
            completed = subprocess.run(
                [str(git), *arguments],
                cwd=working_tree,
                env={},
                check=False,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            self.assertLessEqual(len(completed.stdout), 4096, "git stdout exceeded verification bound")
            self.assertLessEqual(len(completed.stderr), 4096, "git stderr exceeded verification bound")
            self.assertEqual(
                completed.returncode,
                expected_returncode,
                f"git {' '.join(arguments)} returned {completed.returncode}: {completed.stderr.rstrip()}",
            )
            return completed

        def git_output(working_tree: Path, *arguments: str) -> str:
            return run_git(working_tree, *arguments).stdout.rstrip("\n")

        self.assertEqual(git_output(repository, "cat-file", "-t", BASELINE_COMMIT), "commit")
        self.assertEqual(
            git_output(repository, "rev-parse", "--verify", f"{BASELINE_COMMIT}^{{commit}}"), BASELINE_COMMIT
        )
        self.assertEqual(
            run_git(repository, "merge-base", "--is-ancestor", BASELINE_COMMIT, "HEAD").stdout, ""
        )
        self.assertEqual(git_output(repository, "merge-base", BASELINE_COMMIT, "HEAD"), BASELINE_COMMIT)
        self.assertEqual(
            git_output(repository, "rev-parse", "--verify", f"{BASELINE_COMMIT}^{{tree}}"), BASELINE_TREE
        )

        # Prove the ancestry check remains valid after a release commit while
        # rejecting a same-repository HEAD from an unrelated history.
        with tempfile.TemporaryDirectory() as temporary:
            synthetic_repository = Path(temporary).resolve()
            run_git(synthetic_repository, "init", "--quiet")
            marker = synthetic_repository / "marker.txt"
            marker.write_text("baseline\n", encoding="utf-8")
            run_git(synthetic_repository, "add", "--", marker.name)
            commit_arguments = (
                "-c",
                "user.name=Compatibility Test",
                "-c",
                "user.email=compatibility@example.invalid",
                "commit",
                "--quiet",
            )
            run_git(synthetic_repository, *commit_arguments, "-m", "baseline")
            synthetic_baseline = git_output(synthetic_repository, "rev-parse", "HEAD")

            marker.write_text("descendant\n", encoding="utf-8")
            run_git(synthetic_repository, "add", "--", marker.name)
            run_git(synthetic_repository, *commit_arguments, "-m", "descendant")
            self.assertNotEqual(git_output(synthetic_repository, "rev-parse", "HEAD"), synthetic_baseline)
            run_git(synthetic_repository, "merge-base", "--is-ancestor", synthetic_baseline, "HEAD")
            self.assertEqual(
                git_output(synthetic_repository, "merge-base", synthetic_baseline, "HEAD"), synthetic_baseline
            )

            run_git(synthetic_repository, "checkout", "--quiet", "--orphan", "unrelated")
            run_git(synthetic_repository, "rm", "-r", "--force", "--quiet", "--", ".")
            marker.write_text("unrelated\n", encoding="utf-8")
            run_git(synthetic_repository, "add", "--", marker.name)
            run_git(synthetic_repository, *commit_arguments, "-m", "unrelated")
            run_git(
                synthetic_repository,
                "merge-base",
                "--is-ancestor",
                synthetic_baseline,
                "HEAD",
                expected_returncode=1,
            )

        manifest_lines = MANIFEST.read_text(encoding="utf-8").splitlines()
        commit_line = f"- Baseline commit: `{BASELINE_COMMIT}`"
        tree_line = f"- Baseline tree: `{BASELINE_TREE}`"
        self.assertEqual([line for line in manifest_lines if "Baseline commit:" in line], [commit_line])
        self.assertEqual([line for line in manifest_lines if "Baseline tree:" in line], [tree_line])

    def test_original_test_ids_are_frozen(self) -> None:
        self.assertTrue(MANIFEST.is_file(), f"missing manifest: {MANIFEST}")
        manifest = MANIFEST.read_text(encoding="utf-8")
        frozen_ids, declared_count, declared_hash = _parse_manifest(manifest)

        first_id = frozen_ids[0]
        second_id = frozen_ids[1]
        hostile_manifests = {
            "duplicate BEGIN marker": manifest.replace(IDS_BEGIN, f"{IDS_BEGIN}\n{IDS_BEGIN}", 1),
            "duplicate END marker": manifest.replace(IDS_END, f"{IDS_END}\n{IDS_END}", 1),
            "reversed markers": manifest.replace(f"{IDS_BEGIN}\n", "__SWAP_MARKER__\n", 1)
            .replace(f"{IDS_END}\n", f"{IDS_BEGIN}\n", 1)
            .replace("__SWAP_MARKER__\n", f"{IDS_END}\n", 1),
            "duplicate commit line": manifest.replace(
                f"- Baseline commit: `{BASELINE_COMMIT}`",
                f"- Baseline commit: `{BASELINE_COMMIT}`\n- Baseline commit: `{BASELINE_COMMIT}`",
                1,
            ),
            "duplicate count line": manifest.replace(
                f"- Baseline test count: `{declared_count}`",
                f"- Baseline test count: `{declared_count}`\n- Baseline test count: `{declared_count}`",
                1,
            ),
            "malformed count": manifest.replace(
                f"- Baseline test count: `{declared_count}`", "- Baseline test count: `not-an-integer`", 1
            ),
            "duplicate hash line": manifest.replace(
                f"- ID block SHA-256: `{declared_hash}`",
                f"- ID block SHA-256: `{declared_hash}`\n- ID block SHA-256: `{declared_hash}`",
                1,
            ),
            "uppercase hash": manifest.replace(declared_hash, declared_hash.upper(), 1),
            "duplicate ID": manifest.replace(f"{first_id}\n", f"{first_id}\n{first_id}\n", 1),
            "unsorted IDs": manifest.replace(f"{first_id}\n{second_id}\n", f"{second_id}\n{first_id}\n", 1),
            "wrong count": manifest.replace(
                f"- Baseline test count: `{declared_count}`", f"- Baseline test count: `{declared_count + 1}`", 1
            ),
            "wrong hash": manifest.replace(declared_hash, "0" * 64, 1),
            "outside ID": f"{first_id}\n{manifest}",
            "outside bullet ID": f"- {first_id}\n{manifest}",
            "outside inline code ID": f"Outside `{first_id}` reference.\n{manifest}",
            "outside link ID": f"See [{first_id}](https://example.invalid/).\n{manifest}",
            "outside prose ID": f"Outside {first_id} reference.\n{manifest}",
            "indented ID": manifest.replace(f"{first_id}\n", f" {first_id}\n", 1),
            "malformed ID": manifest.replace(f"{first_id}\n", "tests.not-valid!\n", 1),
        }
        for mutation, hostile_manifest in hostile_manifests.items():
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    _parse_manifest(hostile_manifest)

        for non_id_text in (f"prefix{first_id}", f"prefix.{first_id}", f"{first_id}.123"):
            with self.subTest(non_id_text=non_id_text):
                _parse_manifest(f"{non_id_text}\n{manifest}")

        with tempfile.TemporaryDirectory() as temporary:
            export_root = Path(temporary).resolve()
            archive = subprocess.run(
                ["git", "archive", "--format=tar", BASELINE_COMMIT],
                cwd=Path(__file__).parents[1],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as baseline:
                for member in baseline.getmembers():
                    destination = (export_root / member.name).resolve()
                    if export_root not in destination.parents or not (member.isdir() or member.isfile()):
                        raise ValueError(f"unsafe baseline archive member: {member.name!r}")
                baseline.extractall(export_root, filter="data")

            discovery = """\
from pathlib import Path
import sys
import types
import unittest

root = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(root), str(root / "src")]

# Test identities do not depend on executing the external cryptography backend.
# Supply only its import-time names so -S can keep every site directory disabled.
cryptography = types.ModuleType("cryptography")
hazmat = types.ModuleType("cryptography.hazmat")
primitives = types.ModuleType("cryptography.hazmat.primitives")
serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")
asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
for package in (cryptography, hazmat, primitives, asymmetric):
    package.__path__ = []
ed25519.Ed25519PrivateKey = type("Ed25519PrivateKey", (), {})
primitives.serialization = serialization
asymmetric.ed25519 = ed25519
sys.modules.update({
    module.__name__: module
    for module in (cryptography, hazmat, primitives, serialization, asymmetric, ed25519)
})

modules = ["tests." + path.stem for path in sorted((root / "tests").glob("test_*.py"))]
suite = unittest.defaultTestLoader.loadTestsFromNames(modules)

def walk(current):
    for item in current:
        if isinstance(item, unittest.TestSuite):
            yield from walk(item)
        else:
            yield item

tests = list(walk(suite))
failed = [test for test in tests if type(test).__name__ == "_FailedTest"]
if failed:
    raise RuntimeError(f"baseline test import failed: {failed!r}")
print("\\n".join(sorted(test.id() for test in tests)))
"""
            discovered = subprocess.run(
                [str(Path(sys.executable).resolve()), "-I", "-S", "-c", discovery, str(export_root)],
                cwd=export_root,
                env={},
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.splitlines()

        self.assertEqual(frozen_ids, discovered)
        self.assertEqual(declared_count, len(discovered))


if __name__ == "__main__":
    unittest.main()
