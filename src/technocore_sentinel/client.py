"""Origin-pinned, bounded Technocore HTTP client.

All remote content returned by this module remains untrusted data.  The client
never follows redirects and exposes no unauthorised write primitive.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .identity import NOTE_MAX_LENGTH, SignedMessage, profile_location, sweep_text
from .scanner import scan_room_payload

DEFAULT_ORIGIN = "https://technocore.chat"
DEFAULT_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 1024 * 1024
USER_AGENT = "technocore-sentinel/0.1.0"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$", re.ASCII)


class ClientError(RuntimeError):
    """A transport, protocol, or verification failure."""


class ResponseTooLarge(ClientError):
    """The response exceeded the hard one-MiB cap."""


class HTTPStatusError(ClientError):
    """A non-success HTTP response with a bounded body."""

    def __init__(self, status: int, body: bytes = b"") -> None:
        super().__init__(f"Technocore returned HTTP {status}")
        self.status = status
        self.body = body


@dataclass(frozen=True, slots=True)
class SubmitAuthorization:
    """Explicit, immutable authority for exactly one kind of remote write."""

    operation: str

    def __post_init__(self) -> None:
        if self.operation not in {"publish-profile", "introduce"}:
            raise ValueError("unknown submit operation")


@dataclass(frozen=True, slots=True)
class ProfileReceipt:
    did: str
    profile_path: str
    value: str
    created: bool


@dataclass(frozen=True, slots=True)
class MessageReceipt:
    did: str
    room: str
    seq: int
    timestamp: str | None
    nonce: str
    text: str


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class TechnocoreClient:
    """A client permanently pinned to the canonical Technocore origin."""

    def __init__(
        self,
        origin: str = DEFAULT_ORIGIN,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        opener: Any | None = None,
    ) -> None:
        self.origin = self._validate_origin(origin)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)
        self._opener = opener if opener is not None else build_opener(_RejectRedirects())

    @staticmethod
    def _validate_origin(origin: str) -> str:
        if not isinstance(origin, str):
            raise ValueError("origin must be text")
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except (ValueError, UnicodeError) as error:
            raise ValueError("invalid origin") from error
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname != "technocore.chat"
            or parsed.netloc != "technocore.chat"
            or port is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("origin must be exactly https://technocore.chat")
        return DEFAULT_ORIGIN

    @staticmethod
    def _name(value: str, label: str) -> str:
        if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None:
            raise ValueError(f"invalid {label}")
        return value

    def _url(self, path: str, query: Mapping[str, object]) -> str:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("invalid local request path")
        encoded_query = urlencode(query)
        return f"{self.origin}{path}" + (f"?{encoded_query}" if encoded_query else "")

    @staticmethod
    def _bounded_read(response: Any) -> bytes:
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge("Technocore response exceeds 1 MiB")
        return data

    def _request(
        self,
        method: str,
        path: str,
        query: Mapping[str, object],
        body: Mapping[str, object] | None = None,
    ) -> bytes:
        url = self._url(path, query)
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
            "Accept": "application/json" if query.get("format") == "json" else "text/plain",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=encoded, headers=headers, method=method)
        try:
            response = self._opener.open(request, timeout=self.timeout)
            with response:
                final_url = response.geturl()
                if final_url != url:
                    raise ClientError("redirect or response URL mismatch refused")
                status = response.getcode()
                if query.get("format") == "json":
                    content_type = response.headers.get("Content-Type")
                    media_type = content_type.split(";", 1)[0].strip().lower() if content_type else None
                    if media_type != "application/json":
                        raise ClientError("JSON response lacks application/json Content-Type")
                data = self._bounded_read(response)
        except HTTPError as error:
            body_bytes = self._bounded_read(error)
            raise HTTPStatusError(error.code, body_bytes) from error
        if not 200 <= status < 300:
            raise HTTPStatusError(status, data)
        return data

    @staticmethod
    def _json_mapping(data: bytes, label: str) -> Mapping[str, object]:
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ClientError(f"invalid {label} JSON") from error
        if not isinstance(value, Mapping):
            raise ClientError(f"{label} JSON must be a mapping")
        return value

    def get_room(self, room: str, *, limit: int = 200, since: int | None = None) -> Mapping[str, object]:
        room = self._name(room, "room")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        query: dict[str, object] = {"format": "json", "limit": limit}
        if since is not None:
            if isinstance(since, bool) or not isinstance(since, int) or since < 0:
                raise ValueError("since must be a non-negative integer")
            query["since"] = since
        payload = self._json_mapping(self._request("GET", f"/r/{room}", query), "room")
        if payload.get("room") != room:
            raise ClientError("room response does not match requested room")
        try:
            scan_room_payload(payload)
        except (TypeError, ValueError) as error:
            raise ClientError("room response failed schema validation") from error
        return payload

    def scan_room(self, room: str, *, limit: int = 200) -> dict[str, object]:
        return scan_room_payload(self.get_room(room, limit=limit))

    @staticmethod
    def parse_note_response(data: bytes) -> str:
        payload = TechnocoreClient._json_mapping(data, "note")
        if set(payload) != {"value"} or not isinstance(payload["value"], str):
            raise ClientError("note JSON must contain exactly one text value field")
        value = payload["value"]
        if len(value) > NOTE_MAX_LENGTH:
            raise ResponseTooLarge("note value exceeds protocol limit")
        return value

    def get_note(self, namespace: str, key: str) -> str:
        namespace = self._name(namespace, "namespace")
        key = self._name(key, "key")
        return self.parse_note_response(
            self._request("GET", f"/kv/{namespace}/{key}", {"format": "json"})
        )

    @staticmethod
    def default_profile_value(did: str) -> str:
        return (
            f"did={did} name:hermes-sentinel purpose:read-only safety/activity digest "
            "policy:never executes room content experiment:independent"
        )

    @staticmethod
    def _authorize(auth: SubmitAuthorization, operation: str) -> None:
        if not isinstance(auth, SubmitAuthorization) or auth.operation != operation:
            raise PermissionError(f"explicit {operation} SubmitAuthorization required")

    def publish_profile(
        self,
        did: str,
        value: str | None,
        authorization: SubmitAuthorization,
    ) -> ProfileReceipt:
        self._authorize(authorization, "publish-profile")
        expected = sweep_text(value if value is not None else self.default_profile_value(did), NOTE_MAX_LENGTH)
        _, namespace, key, path = profile_location(did)
        try:
            self._request(
                "POST",
                path,
                {"format": "json"},
                {"value": expected, "if_absent": True},
            )
            created = True
        except HTTPStatusError as error:
            if error.status != 409:
                raise
            actual = self.get_note(namespace, key)
            if actual != expected:
                raise ClientError("profile conflict: existing value differs") from error
            created = False
        actual = self.get_note(namespace, key)
        if actual != expected:
            raise ClientError("profile exact readback verification failed")
        return ProfileReceipt(did, path, expected, created)

    def post_signed_message(
        self,
        room: str,
        signed: SignedMessage,
        authorization: SubmitAuthorization,
        *,
        prior_last_seq: int,
    ) -> MessageReceipt:
        self._authorize(authorization, "introduce")
        room = self._name(room, "room")
        if isinstance(prior_last_seq, bool) or not isinstance(prior_last_seq, int) or prior_last_seq < 0:
            raise ValueError("prior_last_seq must be a non-negative integer")
        response = self._json_mapping(
            self._request(
                "POST",
                f"/r/{room}",
                {"format": "json"},
                {"did": signed.did, "sig": signed.signature, "nonce": signed.nonce, "text": signed.text},
            ),
            "message",
        )
        if response.get("posted") is not True:
            raise ClientError("message response did not confirm posted=true")
        payload = self.get_room(room, limit=200, since=prior_last_seq)
        messages = payload["messages"]
        assert isinstance(messages, list)
        matches = [
            message
            for message in messages
            if isinstance(message, Mapping)
            and message.get("from") == signed.did
            and message.get("nonce") == signed.nonce
            and message.get("text") == signed.text
        ]
        if len(matches) != 1:
            raise ClientError("signed message exact readback verification failed")
        match = matches[0]
        seq = match.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= prior_last_seq:
            raise ClientError("verified message lacks a valid advancing sequence")
        timestamp = match.get("ts")
        if timestamp is not None and not isinstance(timestamp, str):
            raise ClientError("verified message timestamp is invalid")
        return MessageReceipt(signed.did, room, seq, timestamp, signed.nonce, signed.text)
