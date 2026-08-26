"""Read-only-by-default command line interface for Technocore Sentinel."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any, Callable, Sequence, TextIO

from .client import SubmitAuthorization, TechnocoreClient
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


def _public_identity(seed: bytes) -> dict[str, str]:
    did = derive_did_key(seed)
    return {"did": did, "profile_path": profile_location(did)[3]}


def _secure_write_json(path: str | os.PathLike[str], value: dict[str, object]) -> None:
    parent, name = _key_location(path)
    parent_descriptor = _open_parent(parent, create=True)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=parent_descriptor,
        )
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
    finally:
        os.close(parent_descriptor)


def _load_nonce(path: str | os.PathLike[str]) -> str | None:
    parent, name = _key_location(path)
    try:
        parent_descriptor = _open_parent(parent, create=False)
    except ValueError:
        if not parent.exists():
            return None
        raise
    try:
        descriptor = os.open(name, _open_flags(os.O_RDONLY), dir_fd=parent_descriptor)
    except FileNotFoundError:
        os.close(parent_descriptor)
        return None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) & 0o077:
            raise ValueError("nonce state must be a secure regular file")
        data = os.read(descriptor, 4097)
        if len(data) > 4096:
            raise ValueError("invalid nonce state")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid nonce state") from error
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    if not isinstance(payload, dict) or set(payload) != {"nonce"} or not isinstance(payload["nonce"], str):
        raise ValueError("invalid nonce state")
    # next_nonce performs exact nonce syntax validation without consuming it.
    next_nonce(payload["nonce"])
    return payload["nonce"]


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

    seed = load_identity(args.key_file)
    public = _public_identity(seed)
    did = public["did"]

    if args.command == "publish-profile":
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

    previous = _load_nonce(args.nonce_file)
    nonce = next_nonce(previous)
    signed = sign_message(seed, args.room, nonce, args.text)
    plan = {
        "action": "introduce",
        "dry_run": not args.submit,
        "method": "POST",
        "target": f"/r/{args.room}?format=json",
        "body": {"did": signed.did, "nonce": signed.nonce, "text": signed.text, "sig": "[redacted]"},
        **public,
    }
    print(json.dumps(plan, sort_keys=True), file=stdout)
    if not args.submit:
        return 0

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
    prior_last_seq = max(sequence_evidence)
    receipt = client.post_signed_message(
        args.room,
        signed,
        SubmitAuthorization("introduce"),
        prior_last_seq=prior_last_seq,
    )
    _secure_write_json(args.nonce_file, {"nonce": receipt.nonce})
    _secure_write_json(
        args.receipt_file,
        {
            "did": receipt.did,
            "profile_path": public["profile_path"],
            "room": receipt.room,
            "seq": receipt.seq,
            "timestamp": receipt.timestamp,
            "nonce": receipt.nonce,
            "text_hash": hashlib.sha256(receipt.text.encode("utf-8")).hexdigest(),
        },
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
