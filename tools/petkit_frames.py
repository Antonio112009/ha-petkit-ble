"""Pure PetKit fountain BLE frame codec and decoders (no bleak, no Home Assistant).

Shared by the CLI in this folder and by the unit tests. Everything here is
side-effect free so captured frames can be replayed offline.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

WRITE_UUID = "0000aaa2-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000aaa1-0000-1000-8000-00805f9b34fb"

HEADER = bytes([0xFA, 0xFC, 0xFD])
TRAILER = 0xFB

TYPE_REQUEST = 1
TYPE_RESPONSE = 2

CMD_BATTERY = 66
CMD_INIT = 73  # WRITES the device id + secret. Never sent by the CLI.
CMD_SET_TIME = 84  # WRITES the clock. Only sent with an explicit flag.
CMD_VERIFY = 86
CMD_FIRMWARE = 200
CMD_STATE = 210
CMD_CONFIG = 211
CMD_DEVICE_INFO = 213
CMD_PUSH = 230

CMD_NAMES = {
    CMD_BATTERY: "battery",
    CMD_INIT: "init",
    CMD_SET_TIME: "set_time",
    CMD_VERIFY: "verify_secret",
    CMD_FIRMWARE: "firmware",
    CMD_STATE: "state",
    CMD_CONFIG: "config",
    CMD_DEVICE_INFO: "device_info",
    CMD_PUSH: "push",
}

# Commands the CLI is allowed to send without an explicit opt-in flag.
READ_ONLY_CMDS = frozenset({CMD_BATTERY, CMD_VERIFY, CMD_FIRMWARE, CMD_STATE, CMD_CONFIG, CMD_DEVICE_INFO})


@dataclass(frozen=True)
class Frame:
    """One decoded protocol frame."""

    cmd: int
    type: int
    seq: int
    payload: bytes
    raw: bytes = b""  # bytes as received; empty for frames built locally

    @property
    def name(self) -> str:
        return CMD_NAMES.get(self.cmd, f"cmd{self.cmd}")


def build_frame(cmd: int, type_: int, seq: int, payload: bytes = b"") -> bytes:
    """FA FC FD | cmd | type | seq | len | 00 | payload | FB (no checksum)."""
    if len(payload) > 0xFF:
        raise ValueError("payload too long")
    return HEADER + bytes([cmd, type_, seq & 0xFF, len(payload), 0x00]) + payload + bytes([TRAILER])


class FrameAssembler:
    """Reassemble frames from notification chunks (a frame can span packets)."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.dropped = bytearray()  # bytes skipped while looking for a frame

    def feed(self, chunk: bytes) -> list[Frame]:
        self._buf.extend(chunk)
        frames: list[Frame] = []
        while True:
            start = self._buf.find(HEADER)
            if start < 0:
                # Keep a possible partial header at the tail.
                keep = len(HEADER) - 1
                self.dropped += self._buf[: max(0, len(self._buf) - keep)]
                del self._buf[: max(0, len(self._buf) - keep)]
                return frames
            if start:
                self.dropped += self._buf[:start]
                del self._buf[:start]
            if len(self._buf) < 8:
                return frames
            total = 8 + self._buf[6] + 1
            if len(self._buf) < total:
                return frames
            raw = bytes(self._buf[:total])
            if raw[-1] != TRAILER:
                # Not a real frame start; skip this header and resync.
                self.dropped += self._buf[: len(HEADER)]
                del self._buf[: len(HEADER)]
                continue
            del self._buf[:total]
            frames.append(Frame(cmd=raw[3], type=raw[4], seq=raw[5], payload=raw[8:-1], raw=raw))


# ---------------------------------------------------------------------------
# Secret candidates (for CMD 86, which only verifies and writes nothing)
# ---------------------------------------------------------------------------


def derive_secret(device_id: bytes) -> bytes:
    """Secret derivation used by PetkitW5BLEMQTT / phldgmn / Jezza PR #203.

    Reverse the id bytes, replace two trailing zero bytes with 13, 37, then
    left-pad with zeros to 8 bytes.
    """
    rev = list(reversed(device_id))
    if len(rev) >= 2 and rev[-1] == 0 and rev[-2] == 0:
        rev[-2], rev[-1] = 13, 37
    return bytes([0] * (8 - len(rev)) + rev)[-8:]


def secret_candidates(info_payload: bytes) -> dict[str, bytes]:
    """Every secret the reference projects would try for this CMD 213 reply."""
    out: dict[str, bytes] = {
        "zero": bytes(8),
        "leet": derive_secret(bytes(6)),  # PR #203 for CTW3: derived from a zero id
    }
    if len(info_payload) >= 8:
        out["derived6"] = derive_secret(info_payload[2:8])  # PR #203, non-CTW3
        out["derived8"] = derive_secret(info_payload[:8])
    return out


def parse_secret_arg(value: str, info_payload: bytes, *, pad_right: bool = False) -> bytes:
    """Resolve --secret: a candidate name or 1..16 hex digits, zero-padded to 8 bytes.

    The padding side for short secrets is unconfirmed: phldgmn left-pads,
    aavdberg right-pads.
    """
    named = secret_candidates(info_payload)
    if value in named:
        return named[value]
    try:
        raw = bytes.fromhex(value.replace(":", "").replace(" ", ""))
    except ValueError:
        raise ValueError(f"not hex and not one of {', '.join(named)}") from None
    if not 1 <= len(raw) <= 8:
        raise ValueError("secret must be 1..8 bytes of hex")
    return raw.ljust(8, b"\x00") if pad_right else raw.rjust(8, b"\x00")


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_device_info(p: bytes) -> dict:
    if len(p) < 8:
        return {"error": f"too short ({len(p)} bytes)"}
    return {
        "id_hex": p[:8].hex(),
        "id_big_endian": int.from_bytes(p[:8], "big"),
        "id_little_endian": int.from_bytes(p[:8], "little"),
        "initialized": any(p[:8]),
        "serial": p[8:].decode("ascii", errors="replace").strip("\x00 "),
    }


def decode_firmware(p: bytes) -> dict:
    if len(p) < 2:
        return {"error": f"too short ({len(p)} bytes)"}
    return {"hardware": p[0], "firmware": p[1], "tail_hex": p[2:].hex()}


def decode_state_ctw3(p: bytes) -> dict:
    """CMD 210 on CTW3 (26+ bytes, 30 on firmware 111)."""
    if len(p) < 26:
        return {"error": f"too short for CTW3 ({len(p)} bytes)"}
    return {
        "power": p[0],
        "suspend": p[1],
        "mode": p[2],  # 1 = normal, 2 = smart
        "electric_status": p[3],  # 2 = on mains per aavdberg
        "dnd": p[4],
        "warn_breakdown": p[5],
        "warn_water_missing": p[6],
        "low_battery": p[7],
        "warn_filter": p[8],
        "pump_runtime_s": struct.unpack_from(">I", p, 9)[0],
        "filter_percent": p[13],
        "running": p[14],
        "pump_runtime_today_s": struct.unpack_from(">I", p, 15)[0],
        "detect_raw": p[19],  # 0x02 while a pet is detected on fw 111
        "supply_mv": struct.unpack_from(">h", p, 20)[0],
        "battery_mv": struct.unpack_from(">h", p, 22)[0],
        "battery_percent": p[24],
        "module_status": p[25],
        "tail_hex": p[26:].hex(),
    }


def decode_state_generic(p: bytes) -> dict:
    """CMD 210 on W4 / W5 / CTW2 (12..18 bytes)."""
    if len(p) < 12:
        return {"error": f"too short ({len(p)} bytes)"}
    out = {
        "power": p[0],
        "mode": p[1],
        "dnd": p[2],
        "warn_breakdown": p[3],
        "warn_water_missing": p[4],
        "warn_filter": p[5],
        "pump_runtime_s": struct.unpack_from(">I", p, 6)[0],
        "filter_percent": p[10],
        "running": p[11],
    }
    if len(p) >= 16:
        out["pump_runtime_today_s"] = struct.unpack_from(">I", p, 12)[0]
    return out


def decode(frame: Frame) -> dict | None:
    """Best-effort decode of a response/push payload; None when unknown."""
    p = frame.payload
    if frame.cmd == CMD_DEVICE_INFO:
        return decode_device_info(p)
    if frame.cmd == CMD_FIRMWARE:
        return decode_firmware(p)
    if frame.cmd == CMD_VERIFY:
        return {"accepted": bool(p) and p[0] == 1}
    if frame.cmd == CMD_STATE:
        return decode_state_ctw3(p) if len(p) >= 26 else decode_state_generic(p)
    if frame.cmd == CMD_BATTERY and len(p) >= 2:
        return {"raw_le": p[0] | (p[1] << 8), "raw_be": (p[0] << 8) | p[1]}
    return None
