"""Frame codec tests for tools/petkit_frames.py using real CTW3 fw 111 payloads.

The CMD 210 payloads come from aavdberg/ha-petkit issue #65.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import petkit_frames as pf

CTW3_STATE = bytes.fromhex("01010102000000000000242bfe080100006fb40014171076640008072307")


def test_build_frame_layout():
    assert pf.build_frame(213, 1, 0).hex() == "fafcfdd501000000fb"
    assert pf.build_frame(86, 1, 2, bytes(8)).hex() == "fafcfd5601020800" + "00" * 8 + "fb"


def test_assembler_handles_split_and_back_to_back_frames():
    a = pf.build_frame(210, 2, 5, CTW3_STATE)
    b = pf.build_frame(230, 1, 9, b"\x01\x02")
    stream = a + b
    asm = pf.FrameAssembler()
    frames = []
    for i in range(0, len(stream), 20):  # 20-byte BLE notifications
        frames += asm.feed(stream[i : i + 20])
    assert [(f.cmd, f.seq) for f in frames] == [(210, 5), (230, 9)]
    assert frames[0].payload == CTW3_STATE


def test_assembler_resyncs_after_garbage():
    asm = pf.FrameAssembler()
    frames = asm.feed(b"\x00\x11" + pf.build_frame(200, 2, 1, b"\x01\x6f"))
    assert len(frames) == 1 and frames[0].payload == b"\x01\x6f"
    assert bytes(asm.dropped) == b"\x00\x11"


def test_frame_keeps_bytes_as_received():
    raw = bytearray(pf.build_frame(200, 2, 1, b"\x01\x6f"))
    raw[7] = 0x05  # reserved byte must survive for inspection
    assert pf.FrameAssembler().feed(bytes(raw))[0].raw == bytes(raw)


def test_payload_containing_trailer_byte_is_not_truncated():
    payload = bytes([0xFB, 0x01, 0xFB])
    frames = pf.FrameAssembler().feed(pf.build_frame(210, 2, 0, payload))
    assert frames[0].payload == payload


def test_decode_ctw3_state_from_issue_65():
    s = pf.decode_state_ctw3(CTW3_STATE)
    assert (s["power"], s["suspend"], s["mode"], s["electric_status"]) == (1, 1, 1, 2)
    assert s["filter_percent"] == 8
    assert s["battery_percent"] == 100
    assert s["pump_runtime_s"] == 0x242BFE
    assert s["pump_runtime_today_s"] == 0x6FB4
    assert s["detect_raw"] == 0
    assert s["tail_hex"] == "08072307"


def test_decode_dispatches_on_payload_length():
    assert "suspend" in pf.decode(pf.Frame(210, 2, 0, CTW3_STATE))
    assert "suspend" not in pf.decode(pf.Frame(210, 2, 0, bytes(12)))


@pytest.mark.parametrize(
    ("device_id", "expected"),
    [
        (bytes(6), "0000000000000d25"),  # PR #203 CTW3: zero id -> 13, 37
        (bytes.fromhex("0000a1b2c3d4"), "0000d4c3b2a10d25"),
        (bytes.fromhex("a1b2c3d4e5f6"), "0000f6e5d4c3b2a1"),
    ],
)
def test_derive_secret(device_id, expected):
    assert pf.derive_secret(device_id).hex() == expected


def test_parse_secret_arg_names_and_hex():
    info = bytes(8) + b"SN123"
    assert pf.parse_secret_arg("zero", info) == bytes(8)
    assert pf.parse_secret_arg("leet", info).hex() == "0000000000000d25"
    assert pf.parse_secret_arg("0102", info).hex() == "0000000000000102"
    assert pf.parse_secret_arg("0102", info, pad_right=True).hex() == "0102000000000000"
    with pytest.raises(ValueError):
        pf.parse_secret_arg("nothex", info)
    with pytest.raises(ValueError):
        pf.parse_secret_arg("00" * 9, info)


def test_write_commands_are_not_on_the_read_only_list():
    for cmd in (73, 84, 220, 221, 222, 225, 226, 83):
        assert cmd not in pf.READ_ONLY_CMDS
