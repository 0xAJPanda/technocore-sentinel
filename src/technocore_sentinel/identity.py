"""Isolated Ed25519 identity, signing, and secure key persistence."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import time
import unicodedata

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MESSAGE_MAX_LENGTH = 4096
NOTE_MAX_LENGTH = 8192

_REJECTED_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
_ROOM_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$", re.ASCII)
_NONCE_PATTERN = re.compile(r"^[0-9]{1,19}$", re.ASCII)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB_MULTICODEC = b"\xed\x01"
_MAX_NONCE = 9_999_999_999_999_999_999


@dataclass(frozen=True, slots=True)
class SignedMessage:
    """A signed Technocore message and the exact payload covered by it."""

    did: str
    signature: str
    nonce: str
    cleaned_text: str
    canonical: str

    @property
    def text(self) -> str:
        """Alias for the swept message text used on the wire."""

        return self.cleaned_text


def _validate_seed(seed: bytes) -> bytes:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return seed


def _base58btc(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + encoded


def derive_did_key(seed: bytes) -> str:
    """Derive a public ``did:key`` from a raw 32-byte Ed25519 seed."""

    private_key = Ed25519PrivateKey.from_private_bytes(_validate_seed(seed))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"did:key:z{_base58btc(_ED25519_PUB_MULTICODEC + public_key)}"


def sign_canonical(seed: bytes, canonical: str) -> str:
    """Sign UTF-8 canonical text and return unpadded base64url."""

    if not isinstance(canonical, str):
        raise ValueError("canonical payload must be text")
    private_key = Ed25519PrivateKey.from_private_bytes(_validate_seed(seed))
    signature = private_key.sign(canonical.encode("utf-8"))
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def sweep_unicode(text: str) -> str:
    """Replace server-rejected Unicode categories with spaces, then trim."""

    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return "".join(
        " " if unicodedata.category(character) in _REJECTED_UNICODE_CATEGORIES else character
        for character in text
    ).strip()


def sweep_text(text: str, limit: int) -> str:
    """Sweep text and enforce a non-empty, inclusive character limit."""

    if type(limit) is not int or limit < 1:
        raise ValueError("text limit must be a positive integer")
    cleaned = sweep_unicode(text)
    if not cleaned:
        raise ValueError("text is empty after Unicode sweep")
    if len(cleaned) > limit:
        raise ValueError(f"text exceeds {limit} characters")
    return cleaned


def sign_message(seed: bytes, room: str, nonce: str, text: str) -> SignedMessage:
    """Validate, sweep, and sign an exact Technocore message payload."""

    _validate_seed(seed)
    if not isinstance(room, str) or _ROOM_PATTERN.fullmatch(room) is None:
        raise ValueError("invalid room")
    if not isinstance(nonce, str) or _NONCE_PATTERN.fullmatch(nonce) is None:
        raise ValueError("nonce must contain 1-19 ASCII digits")
    cleaned = sweep_text(text, MESSAGE_MAX_LENGTH)
    canonical = f"{room}|{nonce}|{cleaned}"
    return SignedMessage(
        did=derive_did_key(seed),
        signature=sign_canonical(seed, canonical),
        nonce=nonce,
        cleaned_text=cleaned,
        canonical=canonical,
    )


def profile_location(did: str) -> tuple[str, str, str, str]:
    """Return the deterministic fingerprint, shard, key, and profile path."""

    if not isinstance(did, str):
        raise ValueError("DID must be a string")
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    namespace = f"did-{fingerprint[:2]}"
    key = fingerprint[2:]
    return fingerprint, namespace, key, f"/kv/{namespace}/{key}"


def _key_location(path: str | os.PathLike[str]) -> tuple[Path, str]:
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str):
        raise TypeError("identity path must be text")
    name = os.path.basename(raw_path)
    if name in {"", ".", ".."}:
        raise ValueError("identity path must have a file basename")
    parent_text = os.path.dirname(raw_path) or "."
    return Path(parent_text), name


def _open_parent(parent: Path, *, create: bool) -> int:
    if create:
        try:
            parent.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass

    try:
        descriptor = os.open(
            parent,
            _open_flags(os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)),
        )
    except FileNotFoundError:
        raise ValueError("identity parent directory does not exist") from None
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("identity parent must be a real directory") from error
        raise

    try:
        parent_status = os.fstat(descriptor)
        if not stat.S_ISDIR(parent_status.st_mode):
            raise ValueError("identity parent must be a real directory")
        if stat.S_IMODE(parent_status.st_mode) & 0o077:
            raise ValueError("identity parent has group or other permissions")
        get_effective_uid = getattr(os, "geteuid", None)
        if (
            callable(get_effective_uid)
            and hasattr(parent_status, "st_uid")
            and parent_status.st_uid != get_effective_uid()
        ):
            raise ValueError("identity parent is not owned by the effective user")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_flags(base: int) -> int:
    return base | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def create_identity(path: str | os.PathLike[str]) -> bytes:
    """Create one isolated seed file exclusively with restrictive permissions."""

    parent, name = _key_location(path)
    parent_descriptor = _open_parent(parent, create=True)
    descriptor: int | None = None
    created = False
    try:
        seed = secrets.token_bytes(32)
        descriptor = os.open(
            name,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        opened_status = os.fstat(descriptor)
        if not stat.S_ISREG(opened_status.st_mode):
            raise ValueError("identity path is not a regular file")
        if stat.S_IMODE(opened_status.st_mode) & 0o077:
            raise ValueError("identity file has group or other permissions")
        os.fchmod(descriptor, 0o600)

        view = memoryview(seed)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("failed to write identity seed")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)

    return seed


def load_identity(path: str | os.PathLike[str]) -> bytes:
    """Load a seed only from a secure, non-symlink regular file."""

    parent, name = _key_location(path)
    parent_descriptor = _open_parent(parent, create=False)

    try:
        descriptor = os.open(
            name,
            _open_flags(os.O_RDONLY),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        os.close(parent_descriptor)
        if error.errno == errno.ELOOP:
            raise ValueError("identity path must not be a symlink") from error
        raise

    try:
        opened_status = os.fstat(descriptor)
        if not stat.S_ISREG(opened_status.st_mode):
            raise ValueError("identity path is not a regular file")
        if stat.S_IMODE(opened_status.st_mode) & 0o077:
            raise ValueError("identity file has group or other permissions")
        if opened_status.st_size != 32:
            raise ValueError("identity seed file must contain exactly 32 bytes")

        chunks: list[bytes] = []
        remaining = 33
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return _validate_seed(b"".join(chunks))
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def next_nonce(previous: str | None = None) -> str:
    """Return a 19-digit-safe, strictly increasing nanosecond nonce."""

    if previous is None:
        previous_value = -1
    elif isinstance(previous, str) and _NONCE_PATTERN.fullmatch(previous) is not None:
        previous_value = int(previous)
    else:
        raise ValueError("previous nonce must contain 1-19 ASCII digits")

    candidate = max(time.time_ns(), previous_value + 1)
    if candidate > _MAX_NONCE:
        raise OverflowError("nonce exceeds the 19-digit Technocore limit")
    return str(candidate)
