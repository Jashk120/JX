"""
control.py – async Unix-socket client for jkaind control plane.

Protocol: line-delimited JSON over Unix 0600 socket.
Requests: {"cmd":"status"} | {"cmd":"peers"} | {"cmd":"submit_tx","payload_hex":"..."}
Response: {"ok":bool,"result":...,"error":...}
StatusReport: node_id, members, peers, ordered_round, decided_round,
              latest_checkpoint_round, checkpoint_roster
"""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Op encoding helpers – must match executor/state/src/op.rs
#   opcode 0x00 Put { key, value }  -> [0x00][u32 BE len(k)][k][u32 BE len(v)][v]
#   opcode 0x01 Delete { key }      -> [0x01][u32 BE len(k)][k]
#   opcode 0x02 MembershipOp (handled by crypto) – not needed here
# ---------------------------------------------------------------------------

OP_PUT: int = 0x00
OP_DELETE: int = 0x01


def encode_put(key: bytes, value: bytes) -> bytes:
    """Encode a KvOp::Put matching Rust's Op::Put::encode()."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes")
    buf = bytearray()
    buf.append(OP_PUT)
    buf.extend(struct.pack(">I", len(key)))
    buf.extend(key)
    buf.extend(struct.pack(">I", len(value)))
    buf.extend(value)
    return bytes(buf)


def encode_delete(key: bytes) -> bytes:
    """Encode a KvOp::Delete matching Rust's Op::Delete::encode()."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    buf = bytearray()
    buf.append(OP_DELETE)
    buf.extend(struct.pack(">I", len(key)))
    buf.extend(key)
    return bytes(buf)


def decode_op(payload: bytes) -> Dict[str, Any]:
    """Decode an Op payload (for debugging / test assertions)."""
    if not payload:
        raise ValueError("empty payload")
    opcode = payload[0]
    cursor = payload[1:]
    if opcode == OP_PUT:
        if len(cursor) < 4:
            raise ValueError("truncated key len")
        klen = struct.unpack(">I", cursor[:4])[0]
        cursor = cursor[4:]
        if len(cursor) < klen:
            raise ValueError("truncated key")
        key = cursor[:klen]
        cursor = cursor[klen:]
        if len(cursor) < 4:
            raise ValueError("truncated value len")
        vlen = struct.unpack(">I", cursor[:4])[0]
        cursor = cursor[4:]
        if len(cursor) < vlen:
            raise ValueError("truncated value")
        value = cursor[:vlen]
        cursor = cursor[vlen:]
        if cursor:
            raise ValueError("trailing bytes")
        return {"op": "Put", "key": key, "value": value}
    if opcode == OP_DELETE:
        if len(cursor) < 4:
            raise ValueError("truncated key len")
        klen = struct.unpack(">I", cursor[:4])[0]
        cursor = cursor[4:]
        if len(cursor) < klen:
            raise ValueError("truncated key")
        key = cursor[:klen]
        cursor = cursor[klen:]
        if cursor:
            raise ValueError("trailing bytes")
        return {"op": "Delete", "key": key}
    raise ValueError(f"unknown opcode 0x{opcode:02x}")


# ---------------------------------------------------------------------------
# Dataclasses mirroring control.rs StatusReport
# ---------------------------------------------------------------------------


@dataclass
class MemberReport:
    node_id: int
    verifying_key: str  # hex


@dataclass
class PeerReport:
    node_id: int
    gossip_addr: str
    reconnect_addr: Optional[str]
    spki_fingerprint: str  # hex


@dataclass
class StatusReport:
    node_id: int
    members: List[MemberReport]
    peers: List[PeerReport]
    ordered_round: int
    decided_round: int
    latest_checkpoint_round: Optional[int]
    checkpoint_roster: List[MemberReport]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StatusReport":
        members = [MemberReport(**m) for m in d.get("members", [])]
        peers = [PeerReport(**p) for p in d.get("peers", [])]
        roster = [MemberReport(**m) for m in d.get("checkpoint_roster", [])]
        return cls(
            node_id=d["node_id"],
            members=members,
            peers=peers,
            ordered_round=d["ordered_round"],
            decided_round=d["decided_round"],
            latest_checkpoint_round=d.get("latest_checkpoint_round"),
            checkpoint_roster=roster,
        )


# ---------------------------------------------------------------------------
# ControlClient
# ---------------------------------------------------------------------------


class ControlError(RuntimeError):
    pass


class ControlClient:
    """
    Async client for jkaind Unix control socket.

    Usage:
        client = ControlClient("/tmp/data-1/jkaind.sock")
        status = await client.status()
        await client.submit_tx(b"hello")
        await client.submit_put(b"key", b"value")

    Alternatively use the classmethod ``connect`` helper.
    """

    def __init__(
        self,
        socket_path: str | Path,
        *,
        timeout: float = 5.0,
        retries: int = 3,
        retry_delay: float = 0.2,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay

    @classmethod
    async def connect(
        cls,
        path: str | Path,
        *,
        timeout: float = 5.0,
    ) -> "ControlClient":
        """Create a client and verify the socket is reachable (one status probe)."""
        client = cls(path, timeout=timeout)
        await client.status()
        return client

    # -- low-level ----------------------------------------------------------

    async def _request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                return await asyncio.wait_for(self._single_request(payload), timeout=self.timeout)
            except (asyncio.TimeoutError, OSError, ConnectionError, ControlError) as exc:
                last_exc = exc
                if attempt < self.retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                continue
        raise ControlError(f"request {payload.get('cmd')} failed after {self.retries} attempts: {last_exc}") from last_exc

    async def _single_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        except FileNotFoundError as e:
            raise ControlError(f"control socket not found: {self.socket_path}") from e
        try:
            line = json.dumps(payload).encode() + b"\n"
            writer.write(line)
            await writer.drain()
            # read one line with timeout handled by caller
            raw = await reader.readline()
            if not raw:
                raise ControlError("control socket closed without response")
            try:
                resp = json.loads(raw.decode())
            except json.JSONDecodeError as e:
                raise ControlError(f"invalid JSON response: {raw!r}") from e
            if not resp.get("ok"):
                err = resp.get("error", "unknown error")
                raise ControlError(err)
            return resp
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -- high-level API -----------------------------------------------------

    async def status(self) -> StatusReport:
        """Fetch StatusReport from the node."""
        resp = await self._request({"cmd": "status"})
        result = resp.get("result")
        if result is None:
            raise ControlError("status: missing result field")
        return StatusReport.from_dict(result)

    async def status_raw(self) -> Dict[str, Any]:
        """Fetch raw status dict (without dataclass conversion)."""
        resp = await self._request({"cmd": "status"})
        result = resp.get("result")
        if result is None:
            raise ControlError("status: missing result field")
        return result

    async def peers(self) -> List[Dict[str, Any]]:
        """Fetch peer list."""
        resp = await self._request({"cmd": "peers"})
        result = resp.get("result") or {}
        return result.get("peers", [])

    async def submit_tx(self, payload: bytes) -> Dict[str, Any]:
        """Submit an opaque transaction payload (hex-encoded on the wire)."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if len(payload) > 1024 * 1024:
            raise ValueError("payload exceeds 1 MiB limit")
        hex_str = payload.hex()
        resp = await self._request({"cmd": "submit_tx", "payload_hex": hex_str})
        return resp.get("result") or {}

    async def submit_put(self, key: bytes, value: bytes) -> Dict[str, Any]:
        """Helper: encode and submit a KvOp::Put."""
        payload = encode_put(key, value)
        return await self.submit_tx(payload)

    async def submit_delete(self, key: bytes) -> Dict[str, Any]:
        """Helper: encode and submit a KvOp::Delete."""
        payload = encode_delete(key)
        return await self.submit_tx(payload)

    # -- sync wrappers (convenience for non-async callers) ----------------

    def status_sync(self) -> StatusReport:
        return asyncio.run(self.status())

    def submit_tx_sync(self, payload: bytes) -> Dict[str, Any]:
        return asyncio.run(self.submit_tx(payload))
