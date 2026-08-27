"""Read-only-by-default command line interface for Technocore Sentinel."""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any, Callable, Sequence, TextIO

from .client import SubmitAuthorization, TechnocoreClient
from .monitor import monitor_room_payload
from .identity import (
    create_identity,
    derive_did_key,
    load_identity,
    next_nonce,
    profile_location,
    sign_message,
    sweep_text,
    NOTE_MAX_LENGTH,
    _key_location,
    _open_flags,
    _open_parent,
)

DEFAULT_KEY_FILE = "state/identity.key"
DEFAULT_NONCE_FILE = "state/nonce.json"
DEFAULT_RECEIPT_FILE = "state/receipt.json"
DEFAULT_MONITOR_STATE_FILE = "state/monitor.json"


def _public_identity(seed: bytes) -> dict[str, str]:
    did = derive_did_key(seed)
    return {"did": did, "profile_path": profile_location(did)[3]}


_STATE_LOCK = ".introduce.lock"
_STATE_JOURNAL = ".introduce.journal"
_MONITOR_LOCK = ".monitor.lock"
_MAX_STATE_BYTES = 16 * 1024
_MAX_MONITOR_ROOMS = 200
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _validate_state_file(descriptor: int, label: str, *, exact_mode: int | None = None) -> None:
    status = os.fstat(descriptor)
    mode = stat.S_IMODE(status.st_mode)
    if not stat.S_ISREG(status.st_mode) or (mode != exact_mode if exact_mode is not None else mode & 0o077):
        raise ValueError(f"{label} must be a secure regular file")


def _read_json_at(
    parent_descriptor: int,
    name: str,
    label: str,
    *,
    exact_mode: int | None = None,
) -> dict[str, object] | None:
    try:
        descriptor = os.open(
            name,
            _open_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == getattr(os, "ELOOP", 40):
            raise ValueError(f"{label} must not be a symlink") from error
        raise
    try:
        _validate_state_file(descriptor, label, exact_mode=exact_mode)
        data = os.read(descriptor, _MAX_STATE_BYTES + 1)
        if len(data) > _MAX_STATE_BYTES:
            raise ValueError(f"invalid {label}")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid {label}") from error
    finally:
        os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError(f"invalid {label}")
    return payload


def _check_target_at(
    parent_descriptor: int,
    name: str,
    label: str,
    *,
    exact_mode: int | None = None,
) -> None:
    """Reject existing symlink, special, or insecure targets."""
    try:
        status = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(status.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    mode = stat.S_IMODE(status.st_mode)
    if not stat.S_ISREG(status.st_mode) or (mode != exact_mode if exact_mode is not None else mode & 0o077):
        raise ValueError(f"{label} must be a secure regular file")
    try:
        descriptor = os.open(
            name,
            _open_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        if error.errno == getattr(os, "ELOOP", 40):
            raise ValueError(f"{label} must not be a symlink") from error
        raise
    try:
        _validate_state_file(descriptor, label, exact_mode=exact_mode)
    finally:
        os.close(descriptor)


def _write_json_at(parent_descriptor: int, name: str, value: dict[str, object], label: str) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > _MAX_STATE_BYTES:
        raise ValueError(f"invalid {label}")
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        _check_target_at(parent_descriptor, name, label)
        descriptor = os.open(
            temporary,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=parent_descriptor,
        )
        _validate_state_file(descriptor, label)
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("failed to write state")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        # Recheck immediately before replacement. The transaction lock prevents
        # cooperating writers from changing this target between the two checks.
        _check_target_at(parent_descriptor, name, label)
        os.replace(temporary, name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        raise


def _validate_nonce_payload(payload: dict[str, object] | None) -> str | None:
    if payload is None:
        return None
    if set(payload) != {"nonce"} or not isinstance(payload["nonce"], str):
        raise ValueError("invalid nonce state")
    next_nonce(payload["nonce"])
    return payload["nonce"]


def _load_nonce(path: str | os.PathLike[str]) -> str | None:
    parent, name = _key_location(path)
    try:
        parent_descriptor = _open_parent(parent, create=False)
    except ValueError:
        if not parent.exists():
            return None
        raise
    try:
        return _validate_nonce_payload(_read_json_at(parent_descriptor, name, "nonce state"))
    finally:
        os.close(parent_descriptor)


def _state_location(nonce_path: str, receipt_path: str) -> tuple[Path, str, str]:
    nonce_parent, nonce_name = _key_location(nonce_path)
    receipt_parent, receipt_name = _key_location(receipt_path)
    if os.path.abspath(nonce_parent) != os.path.abspath(receipt_parent):
        raise ValueError("nonce and receipt state must share one secure parent directory")
    if nonce_name == receipt_name or nonce_name in {_STATE_LOCK, _STATE_JOURNAL} or receipt_name in {_STATE_LOCK, _STATE_JOURNAL}:
        raise ValueError("state filenames must be distinct from transaction files")
    return nonce_parent, nonce_name, receipt_name


def _recover_state(parent_descriptor: int, nonce_name: str, receipt_name: str) -> None:
    journal = _read_json_at(parent_descriptor, _STATE_JOURNAL, "state journal")
    if journal is None:
        return
    if set(journal) != {"nonce", "receipt"} or not isinstance(journal["nonce"], dict) or not isinstance(journal["receipt"], dict):
        raise ValueError("invalid state journal")
    journal_nonce_payload = journal["nonce"]
    receipt_payload = journal["receipt"]
    journal_nonce = _validate_nonce_payload(journal_nonce_payload)
    assert journal_nonce is not None
    if receipt_payload.get("nonce") != journal_nonce:
        raise ValueError("state journal nonce and receipt do not match")
    current_nonce = _validate_nonce_payload(_read_json_at(parent_descriptor, nonce_name, "nonce state"))
    if current_nonce is None or int(current_nonce) < int(journal_nonce):
        _write_json_at(parent_descriptor, receipt_name, receipt_payload, "receipt state")
        _write_json_at(parent_descriptor, nonce_name, journal_nonce_payload, "nonce state")
    elif current_nonce == journal_nonce:
        _write_json_at(parent_descriptor, receipt_name, receipt_payload, "receipt state")
    # A newer nonce proves this journal is stale; never roll it back.
    os.unlink(_STATE_JOURNAL, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


@contextmanager
def _locked_state(nonce_path: str, receipt_path: str) -> Iterator[tuple[int, str, str]]:
    parent, nonce_name, receipt_name = _state_location(nonce_path, receipt_path)
    parent_descriptor = _open_parent(parent, create=True)
    lock_descriptor = -1
    try:
        os.fchmod(parent_descriptor, 0o700)
        _check_target_at(parent_descriptor, _STATE_LOCK, "state lock")
        lock_descriptor = os.open(
            _STATE_LOCK,
            _open_flags(os.O_RDWR | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)),
            0o600,
            dir_fd=parent_descriptor,
        )
        _validate_state_file(lock_descriptor, "state lock")
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _recover_state(parent_descriptor, nonce_name, receipt_name)
        _check_target_at(parent_descriptor, nonce_name, "nonce state")
        _check_target_at(parent_descriptor, receipt_name, "receipt state")
        yield parent_descriptor, nonce_name, receipt_name
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        os.close(parent_descriptor)


def _commit_state(
    parent_descriptor: int,
    nonce_name: str,
    receipt_name: str,
    nonce_payload: dict[str, object],
    receipt_payload: dict[str, object],
) -> None:
    journal: dict[str, object] = {"nonce": nonce_payload, "receipt": receipt_payload}
    _write_json_at(parent_descriptor, _STATE_JOURNAL, journal, "state journal")
    _recover_state(parent_descriptor, nonce_name, receipt_name)


def _validate_monitor_state(payload: dict[str, object] | None) -> dict[str, int]:
    if payload is None:
        return {}
    version = payload.get("version")
    if set(payload) != {"rooms", "version"} or version != 1 or isinstance(version, bool):
        raise ValueError("invalid monitor state")
    rooms = payload.get("rooms")
    if not isinstance(rooms, dict) or len(rooms) > _MAX_MONITOR_ROOMS:
        raise ValueError("invalid monitor state")
    validated: dict[str, int] = {}
    for room, cursor in rooms.items():
        try:
            TechnocoreClient._name(room, "room")
        except ValueError as error:
            raise ValueError("invalid monitor state") from error
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ValueError("invalid monitor state")
        validated[room] = cursor
    return validated


@contextmanager
def _locked_monitor_state(state_path: str | os.PathLike[str]) -> Iterator[tuple[int, str, dict[str, int]]]:
    parent, state_name = _key_location(state_path)
    if state_name in {_MONITOR_LOCK, _STATE_LOCK, _STATE_JOURNAL}:
        raise ValueError("monitor state filename must be distinct from transaction files")
    parent_descriptor = _open_parent(parent, create=True)
    lock_descriptor = -1
    try:
        os.fchmod(parent_descriptor, 0o700)
        _check_target_at(parent_descriptor, state_name, "monitor state", exact_mode=0o600)
        _check_target_at(parent_descriptor, _MONITOR_LOCK, "monitor lock")
        lock_descriptor = os.open(
            _MONITOR_LOCK,
            _open_flags(os.O_RDWR | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)),
            0o600,
            dir_fd=parent_descriptor,
        )
        _validate_state_file(lock_descriptor, "monitor lock")
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _check_target_at(parent_descriptor, state_name, "monitor state", exact_mode=0o600)
        rooms = _validate_monitor_state(
            _read_json_at(parent_descriptor, state_name, "monitor state", exact_mode=0o600)
        )
        yield parent_descriptor, state_name, rooms
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        os.close(parent_descriptor)


def _filter_monitor_report(report: dict[str, object], minimum_severity: str) -> dict[str, object]:
    findings = report.get("findings")
    raw_categories = report.get("category_counts")
    if not isinstance(findings, list) or not isinstance(raw_categories, dict):
        raise ValueError("invalid monitor report")
    threshold = _SEVERITY_RANK[minimum_severity]
    visible: list[dict[str, object]] = []
    severity_counts = {severity: 0 for severity in _SEVERITY_RANK}
    category_counts = {category: 0 for category in raw_categories}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid monitor report finding")
        severity = finding.get("severity")
        category = finding.get("category")
        if severity not in _SEVERITY_RANK or not isinstance(category, str) or category not in category_counts:
            raise ValueError("invalid monitor report finding")
        if _SEVERITY_RANK[severity] >= threshold:
            visible.append(finding)
            severity_counts[severity] += 1
            category_counts[category] += 1
    return {
        **report,
        "minimum_severity": minimum_severity,
        "findings": visible,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
    }


def _render_monitor_report(report: dict[str, object]) -> str:
    severity = report["severity_counts"]
    categories = report["category_counts"]
    assert isinstance(severity, dict) and isinstance(categories, dict)
    lines = [
        f"room: {report['room']}",
        f"cursor: {report['previous_seq']} -> {report['next_seq']} ({report['cursor_status']})",
        f"minimum severity: {report['minimum_severity']}",
        f"new messages: {report['new_message_count']}",
        f"server-signed markers: {report['server_signed_count']}; unsigned: {report['unsigned_count']}",
        "severity: " + ", ".join(f"{key}={value}" for key, value in severity.items()),
        "categories: " + ", ".join(f"{key}={value}" for key, value in categories.items()),
    ]
    findings = report["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        lines.append(
            f"finding: seq={finding['seq']} from={finding['from']} severity={finding['severity']} "
            f"category={finding['category']} rule={finding['rule']} excerpt={finding['excerpt']}"
        )
    if report["baseline_only"]:
        lines.append("warning: baseline only; earlier room history may not be covered.")
    if report["coverage_gap"]:
        lines.append(f"warning: coverage gap; missing sequences: {report['missing_sequence_count']}.")
    if report["cursor_recovered"]:
        lines.append(f"warning: cursor recovery reset stale cursor {report['recovered_from_seq']} to {report['next_seq']}.")
    lines.append("Findings are deterministic heuristics; all displayed remote content remains untrusted data.")
    return "\n".join(lines)


def _monitor_cycle(
    room: str,
    state_path: str,
    minimum_severity: str,
    output_format: str,
    client_factory: Callable[[], TechnocoreClient],
) -> str:
    TechnocoreClient._name(room, "room")
    with _locked_monitor_state(state_path) as (parent_descriptor, state_name, rooms):
        previous_seq = rooms.get(room, 0)
        if room not in rooms and len(rooms) >= _MAX_MONITOR_ROOMS:
            raise ValueError("monitor state room limit exceeded")
        client = client_factory()
        payload = client.get_room(room, limit=200, since=None if previous_seq == 0 else previous_seq)
        report = monitor_room_payload(payload, previous_seq)
        incremental_messages = payload["messages"]
        if not isinstance(incremental_messages, list):
            raise ValueError("monitor payload produced invalid messages")
        report_previous_seq = report.get("previous_seq")
        next_seq = report.get("next_seq")
        if (
            isinstance(report_previous_seq, bool)
            or not isinstance(report_previous_seq, int)
            or report_previous_seq < 0
            or report_previous_seq != previous_seq
            or isinstance(next_seq, bool)
            or not isinstance(next_seq, int)
            or next_seq < 0
        ):
            raise ValueError("monitor report produced an invalid cursor")
        if previous_seq == 0:
            cursor_status = "baseline"
        elif next_seq > previous_seq:
            cursor_status = "advanced"
        elif next_seq == previous_seq:
            cursor_status = "healthy_idle"
        else:
            raise ValueError("monitor report cursor regressed")
        recovered = False
        recovered_from: int | None = None

        if previous_seq > 0 and not incremental_messages:
            head_payload = client.get_room(room, limit=200, since=None)
            head_report = monitor_room_payload(head_payload, 0)
            head_cursor = head_report["next_seq"]
            if isinstance(head_cursor, bool) or not isinstance(head_cursor, int) or head_cursor < 0:
                raise ValueError("monitor head report produced an invalid cursor")
            if head_cursor == previous_seq:
                cursor_status = "healthy_idle"
            elif head_cursor < previous_seq:
                report = head_report
                cursor_status = "recovered_baseline"
                recovered = True
                recovered_from = previous_seq
            else:
                raise RuntimeError("empty incremental response contradicts newer room head")

        report.update(
            cursor_status=cursor_status,
            cursor_recovered=recovered,
            recovered_from_seq=recovered_from,
        )
        visible_report = _filter_monitor_report(report, minimum_severity)
        rendered = json.dumps(visible_report, sort_keys=True) if output_format == "json" else _render_monitor_report(visible_report)

        next_seq = report["next_seq"]
        if isinstance(next_seq, bool) or not isinstance(next_seq, int) or next_seq < 0:
            raise ValueError("monitor report produced an invalid cursor")
        updated_rooms = dict(rooms)
        updated_rooms[room] = next_seq
        if len(updated_rooms) > _MAX_MONITOR_ROOMS:
            raise ValueError("monitor state room limit exceeded")
        _write_json_at(
            parent_descriptor,
            state_name,
            {"rooms": updated_rooms, "version": 1},
            "monitor state",
        )
    return rendered


def _render_digest(digest: dict[str, object]) -> str:
    lines = [
        f"room: {digest['room']}",
        f"sequence: {digest['first_seq']}..{digest['last_seq']}",
        f"messages: {digest['scanned_count']} (signed {digest['signed_count']}, unsigned {digest['unsigned_count']})",
        "severity: " + ", ".join(f"{key}={value}" for key, value in digest["severity_counts"].items()),  # type: ignore[union-attr]
        "categories: " + ", ".join(f"{key}={value}" for key, value in digest["category_counts"].items()),  # type: ignore[union-attr]
    ]
    examples = digest["examples"]
    assert isinstance(examples, dict)
    for category, entries in examples.items():
        if entries:
            lines.append(f"{category} examples:")
            for entry in entries:
                lines.append(
                    f"  seq={entry['seq']} from={entry['from']} severity={entry['severity']} "
                    f"rule={entry['rule']} excerpt={entry['excerpt']}"
                )
    lines.append("Findings are deterministic heuristics, not claims about a sender's intent.")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="technocore-sentinel")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity", help="create or inspect the isolated DID")
    identity_commands = identity.add_subparsers(dest="identity_command", required=True)
    identity_init = identity_commands.add_parser("init", help="create a local Ed25519 key")
    identity_init.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    identity_show = identity_commands.add_parser("show", help="show public identity data")
    identity_show.add_argument("--key-file", default=DEFAULT_KEY_FILE)

    scan = subparsers.add_parser("scan", help="GET and scan untrusted room content")
    scan.add_argument("--room", default="lobby")
    scan.add_argument("--limit", type=int, default=200)
    scan.add_argument("--format", choices=("text", "json"), default="text")

    monitor = subparsers.add_parser("monitor", help="GET and report one incremental room window")
    monitor.add_argument("--room", default="lobby")
    monitor.add_argument("--state-file", default=DEFAULT_MONITOR_STATE_FILE)
    monitor.add_argument("--format", choices=("text", "json"), default="text")
    monitor.add_argument("--min-severity", choices=("low", "medium", "high"), default="low")

    publish = subparsers.add_parser("publish-profile", help="plan or publish a public DID profile")
    publish.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    publish.add_argument("--value")
    publish.add_argument("--submit", action="store_true")

    introduce = subparsers.add_parser("introduce", help="plan or post a signed introduction")
    introduce.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    introduce.add_argument("--nonce-file", default=DEFAULT_NONCE_FILE)
    introduce.add_argument("--receipt-file", default=DEFAULT_RECEIPT_FILE)
    introduce.add_argument("--room", default="lobby")
    introduce.add_argument("--text", required=True)
    introduce.add_argument("--submit", action="store_true")
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    client_factory: Callable[[], TechnocoreClient] = TechnocoreClient,
    stdout: TextIO = sys.stdout,
) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "identity":
        seed = create_identity(args.key_file) if args.identity_command == "init" else load_identity(args.key_file)
        print(json.dumps(_public_identity(seed), sort_keys=True), file=stdout)
        return 0

    if args.command == "scan":
        digest = client_factory().scan_room(args.room, limit=args.limit)
        print(json.dumps(digest, sort_keys=True) if args.format == "json" else _render_digest(digest), file=stdout)
        return 0

    if args.command == "monitor":
        rendered = _monitor_cycle(args.room, args.state_file, args.min_severity, args.format, client_factory)
        print(rendered, file=stdout)
        return 0

    if args.command == "publish-profile":
        seed = load_identity(args.key_file)
        public = _public_identity(seed)
        did = public["did"]
        value = sweep_text(
            args.value if args.value is not None else TechnocoreClient.default_profile_value(did),
            NOTE_MAX_LENGTH,
        )
        plan = {
            "action": "publish-profile",
            "dry_run": not args.submit,
            "method": "POST",
            "target": f"{public['profile_path']}?format=json",
            "body": {"value": value, "if_absent": True},
            **public,
        }
        print(json.dumps(plan, sort_keys=True), file=stdout)
        if not args.submit:
            return 0
        receipt = client_factory().publish_profile(
            did,
            value,
            SubmitAuthorization("publish-profile"),
        )
        print(json.dumps({"verified": True, "created": receipt.created, **public}, sort_keys=True), file=stdout)
        return 0

    if not args.submit:
        seed = load_identity(args.key_file)
        public = _public_identity(seed)
        nonce = next_nonce(_load_nonce(args.nonce_file))
        signed = sign_message(seed, args.room, nonce, args.text)
        plan = {
            "action": "introduce",
            "dry_run": True,
            "method": "POST",
            "target": f"/r/{args.room}?format=json",
            "body": {"did": signed.did, "nonce": signed.nonce, "text": signed.text, "sig": "[redacted]"},
            **public,
        }
        print(json.dumps(plan, sort_keys=True), file=stdout)
        return 0

    with _locked_state(args.nonce_file, args.receipt_file) as (parent_descriptor, nonce_name, receipt_name):
        previous = _validate_nonce_payload(_read_json_at(parent_descriptor, nonce_name, "nonce state"))
        nonce = next_nonce(previous)
        seed = load_identity(args.key_file)
        public = _public_identity(seed)
        signed = sign_message(seed, args.room, nonce, args.text)
        # Drop the only local reference before any network operation. Python does
        # not guarantee in-place wiping of immutable bytes, so it is never copied,
        # persisted, or printed.
        del seed
        plan = {
            "action": "introduce",
            "dry_run": False,
            "method": "POST",
            "target": f"/r/{args.room}?format=json",
            "body": {"did": signed.did, "nonce": signed.nonce, "text": signed.text, "sig": "[redacted]"},
            **public,
        }
        print(json.dumps(plan, sort_keys=True), file=stdout)

        client = client_factory()
        before = client.get_room(args.room, limit=1)
        messages = before.get("messages")
        if not isinstance(messages, list):
            raise ValueError("room messages must be a list")
        sequence_evidence = [0]
        for index, message in enumerate(messages):
            if not isinstance(message, Mapping):
                raise ValueError(f"message {index} must be a mapping")
            seq = message.get("seq")
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise ValueError(f"message {index} seq must be a non-negative integer")
            sequence_evidence.append(seq)
        last_seq = before.get("last_seq")
        if isinstance(last_seq, int) and not isinstance(last_seq, bool) and last_seq >= 0:
            sequence_evidence.append(last_seq)
        receipt = client.post_signed_message(
            args.room,
            signed,
            SubmitAuthorization("introduce"),
            prior_last_seq=max(sequence_evidence),
        )
        receipt_payload: dict[str, object] = {
            "did": receipt.did,
            "profile_path": public["profile_path"],
            "room": receipt.room,
            "seq": receipt.seq,
            "timestamp": receipt.timestamp,
            "nonce": receipt.nonce,
            "text_hash": hashlib.sha256(receipt.text.encode("utf-8")).hexdigest(),
        }
        _commit_state(
            parent_descriptor,
            nonce_name,
            receipt_name,
            {"nonce": receipt.nonce},
            receipt_payload,
        )

    print(
        json.dumps(
            {"verified": True, "did": receipt.did, "room": receipt.room, "seq": receipt.seq, "nonce": receipt.nonce},
            sort_keys=True,
        ),
        file=stdout,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(argv)
    except (OSError, ValueError, RuntimeError, PermissionError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
