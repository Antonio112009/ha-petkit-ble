"""Tests for the cloud secret path, CMD 66/84 decoding and poll resilience.

Byte fixtures were captured from a CTW3UV (Eversweet Max Cordless,
firmware 111) bound to the PetKit app.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.petkit_ble.ble_client import PetkitBleClient, PetkitFountainData, parse_battery_mv
from custom_components.petkit_ble.cloud import match_cloud_secret, normalize_mac
from custom_components.petkit_ble.const import MAX_BACKOFF_INTERVAL, MAX_STALE_POLLS, POLL_INTERVAL
from custom_components.petkit_ble.coordinator import (
    _DrinkCountState,
    _track_drink_event_into,
    backoff_interval,
)
from custom_components.petkit_ble.protocol import (
    build_init_payload,
    build_time_sync_payload,
    normalize_secret,
    parse_device_id,
    parse_secret_hex,
)

# Real frames, CTW3UV fw 111.
INFO_213 = bytes.fromhex("0000000017a1b2c33230323630313031573030303031")
STATE_210 = bytes.fromhex("0101020200000000000000c69e62000000707700143d1082640026049004")
CONFIG_211 = bytes.fromhex("030300190e10010200000000")
BATTERY_66 = bytes.fromhex("108864")


def test_device_id_matches_cloud_id():
    assert parse_device_id(INFO_213) == 396473027
    assert INFO_213[8:].decode() == "20260101W00001"


def test_cloud_secret_is_left_padded_to_eight_bytes():
    assert normalize_secret(bytes.fromhex("a1b2c3d4e5f6")).hex() == "0000a1b2c3d4e5f6"
    assert parse_secret_hex("a1b2c3d4e5f6").hex() == "0000a1b2c3d4e5f6"
    assert parse_secret_hex(" A1:B2:C3:D4:E5:F6 ").hex() == "0000a1b2c3d4e5f6"
    assert normalize_secret(None) == bytes(8)


@pytest.mark.parametrize("bad", ["", "xyz", "00" * 9, "abc"])
def test_parse_secret_hex_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_secret_hex(bad)


def test_init_payload_pads_secret_the_same_way():
    payload = build_init_payload(396473027, bytes.fromhex("a1b2c3d4e5f6"))
    assert bytes(payload).hex() == "0000000017a1b2c3" + "0000a1b2c3d4e5f6"


def test_time_sync_carries_local_offset():
    assert build_time_sync_payload()[-1] == 13
    assert build_time_sync_payload(0)[-1] == 12
    assert build_time_sync_payload(-5)[-1] == 7
    assert build_time_sync_payload(3)[-1] == 15


def test_battery_reply_ctw3_is_big_endian_millivolts():
    assert parse_battery_mv(BATTERY_66) == 4232
    assert parse_battery_mv(bytes([0x10, 0x0E])) == 0x0E10  # legacy 2-byte LE
    assert parse_battery_mv(b"") == 0


def test_real_ctw3_state_and_config_frames():
    data = PetkitFountainData(alias="CTW3")
    PetkitBleClient._parse_state_ctw3(data, STATE_210)
    assert (data.power_status, data.suspend_status, data.mode) == (1, 1, 2)
    assert data.electric_status == 2 and data.is_on_ac_power
    assert data.filter_percent == 98
    assert data.battery_percent == 100 and data.battery_voltage_mv == 4226
    assert data.running_status == 0 and data.detect_status == 0
    # Firmware 111 does answer CMD 211.
    PetkitBleClient._parse_config_ctw3(data, CONFIG_211)
    assert (data.smart_time_on, data.smart_time_off) == (3, 3)
    assert (data.battery_work_time, data.battery_sleep_time) == (25, 3600)
    assert (data.led_switch, data.led_brightness) == (1, 2)
    assert data.config_loaded


def test_cloud_secret_matched_by_mac_or_id():
    feeder = SimpleNamespace(
        id=400000002, mac="aabbccddeeff", secret="1111111111111111"
    )  # gitleaks:allow (dummy value)
    fountain = SimpleNamespace(id=396473027, mac="a4c138aabbcc", secret="a1b2c3d4e5f6")  # gitleaks:allow (dummy value)
    pet = SimpleNamespace(id=1)
    devices = [pet, feeder, fountain]
    assert normalize_mac("A4:C1:38:AA:BB:CC") == "a4c138aabbcc"
    assert match_cloud_secret(devices, "A4:C1:38:AA:BB:CC", 0) == "a1b2c3d4e5f6"
    assert match_cloud_secret(devices, "", 396473027) == "a1b2c3d4e5f6"
    assert match_cloud_secret(devices, "11:22:33:44:55:66", 5) is None
    assert match_cloud_secret([SimpleNamespace(id=396473027, mac=None, secret=None)], "", 396473027) is None


def test_backoff_starts_only_after_the_stale_window():
    for failed in range(MAX_STALE_POLLS + 1):
        assert backoff_interval(failed) == POLL_INTERVAL
    assert backoff_interval(MAX_STALE_POLLS + 1) == POLL_INTERVAL * 2
    assert backoff_interval(MAX_STALE_POLLS + 2) == POLL_INTERVAL * 4
    assert backoff_interval(50) == MAX_BACKOFF_INTERVAL


async def test_drink_edge_returns_delta_and_sets_last_drink(monkeypatch):
    from datetime import UTC, datetime

    from custom_components.petkit_ble import coordinator as coord

    now = datetime(2026, 11, 20, 16, 0, tzinfo=UTC)
    monkeypatch.setattr(coord, "dt_util", MagicMock(now=lambda: now))
    state = _DrinkCountState(date_iso="2026-11-20")
    store = MagicMock(async_save=AsyncMock())

    idle = PetkitFountainData(alias="CTW3")
    assert await _track_drink_event_into(state, store, idle) == 0
    drinking = PetkitFountainData(alias="CTW3", detect_status=1)
    assert await _track_drink_event_into(state, store, drinking) == 1
    assert drinking.drink_event_count == 1 and drinking.last_drink_time == now
    store.async_save.assert_awaited_once_with({"count": 1, "date": "2026-11-20", "last": now.isoformat()})
    # Still drinking on the next poll: no second event.
    assert await _track_drink_event_into(state, store, PetkitFountainData(alias="CTW3", detect_status=1)) == 0


def test_clock_sync_is_skipped_when_disabled():
    """With sync_clock off, authentication must not write the clock (CMD 84)."""
    import asyncio

    from custom_components.petkit_ble.const import CMD_AUTH_VERIFY, CMD_GET_DEVICE_INFO, CMD_SET_TIME

    async def run(sync_clock: bool) -> list[int]:
        client = PetkitBleClient(MagicMock(), sync_clock=sync_clock)
        sent: list[int] = []

        async def fake_send(cmd, type_, data, **_kw):
            sent.append(cmd)
            return {CMD_GET_DEVICE_INFO: INFO_213, CMD_AUTH_VERIFY: b"\x01"}.get(cmd, b"\x01")

        client._send_and_wait = fake_send
        await client._authenticate("CTW3", bytes.fromhex("a1b2c3d4e5f6"))
        return sent

    assert CMD_SET_TIME not in asyncio.run(run(False))
    assert CMD_SET_TIME in asyncio.run(run(True))


async def test_rejected_secret_raises_auth_error():
    from custom_components.petkit_ble.ble_client import PetkitAuthError
    from custom_components.petkit_ble.const import CMD_GET_DEVICE_INFO

    client = PetkitBleClient(MagicMock(), sync_clock=False)

    async def fake_send(cmd, type_, data, **_kw):
        return INFO_213 if cmd == CMD_GET_DEVICE_INFO else b"\x00"

    client._send_and_wait = fake_send
    with pytest.raises(PetkitAuthError):
        await client._authenticate("CTW3", bytes(8))


def test_poll_interval_option_is_clamped():
    from custom_components.petkit_ble.const import MAX_POLL_INTERVAL, MIN_POLL_INTERVAL
    from custom_components.petkit_ble.coordinator import clamp_poll_interval

    assert clamp_poll_interval(20) == 20
    assert clamp_poll_interval("30") == 30
    assert clamp_poll_interval(1) == MIN_POLL_INTERVAL
    assert clamp_poll_interval(99999) == MAX_POLL_INTERVAL
    assert clamp_poll_interval(None) == POLL_INTERVAL
    assert clamp_poll_interval("fast") == POLL_INTERVAL


def test_backoff_follows_the_configured_interval():
    assert backoff_interval(0, 20) == 20
    assert backoff_interval(MAX_STALE_POLLS, 20) == 20
    assert backoff_interval(MAX_STALE_POLLS + 1, 20) == 40
    assert backoff_interval(50, 20) == MAX_BACKOFF_INTERVAL
    # A slow configured interval is never shortened by the cap.
    assert backoff_interval(50, 600) >= 600


async def test_debug_log_never_contains_the_secret(caplog):
    import logging

    from custom_components.petkit_ble.const import CMD_AUTH_VERIFY, CMD_GET_STATE

    client = PetkitBleClient(MagicMock(), sync_clock=False)
    client._client = MagicMock(write_gatt_char=AsyncMock())
    secret = bytes.fromhex("0000a1b2c3d4e5f6")  # gitleaks:allow (dummy value)
    with caplog.at_level(logging.DEBUG, logger="custom_components.petkit_ble.ble_client"):
        await client._send_and_wait(CMD_AUTH_VERIFY, 1, list(secret), timeout=0.01, quiet=True)
        await client._send_and_wait(CMD_GET_STATE, 1, [], timeout=0.01, quiet=True)
    assert "a1b2c3d4e5f6" not in caplog.text
    assert "TX CMD 86: <secret hidden>" in caplog.text
    assert "TX CMD 210: fafcfdd2" in caplog.text
