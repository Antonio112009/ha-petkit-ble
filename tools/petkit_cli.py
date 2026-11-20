# /// script
# requires-python = ">=3.11"
# dependencies = ["bleak>=3.1"]
# ///
"""Read-only BLE probe for PetKit fountains (CTW3 / Eversweet Max Cordless first).

Run with uv (no venv needed):

    uv run tools/petkit_cli.py scan
    uv run tools/petkit_cli.py probe
    uv run tools/petkit_cli.py status --secret <hex|zero|leet|derived6|derived8>
    uv run tools/petkit_cli.py listen --secret <...> --seconds 300

Safety: this tool never sends CMD 73 (init, overwrites the pairing secret) and
has no code path for mode/settings/filter writes. The only write-like command
is CMD 84 (clock sync), sent only with --set-time.

macOS hides BLE MAC addresses, so devices are matched by name (Petkit_*).
Close the PetKit phone app first: the fountain accepts one connection at a time.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

sys.path.insert(0, str(Path(__file__).resolve().parent))

import petkit_frames as pf

PETKIT_EPOCH = 946684800  # 2000-01-01 UTC
NAME_PREFIX = "Petkit_"


def _is_petkit(dev: BLEDevice, adv: AdvertisementData, name_filter: str | None) -> bool:
    name = adv.local_name or dev.name or ""
    if name_filter:
        return name_filter.lower() in name.lower() or name_filter.lower() == dev.address.lower()
    return name.lower().startswith(NAME_PREFIX.lower())


def _print_adv(dev: BLEDevice, adv: AdvertisementData) -> None:
    print(f"- {adv.local_name or dev.name!s}  address={dev.address}  rssi={adv.rssi}")
    print(f"    service_uuids: {adv.service_uuids}")
    for cid, data in adv.manufacturer_data.items():
        print(f"    manufacturer 0x{cid:04x}: {data.hex()}")
    for uuid, data in adv.service_data.items():
        print(f"    service_data {uuid}: {data.hex()}")
    if adv.tx_power is not None:
        print(f"    tx_power: {adv.tx_power}")


async def _find(name_filter: str | None, timeout: float) -> tuple[BLEDevice, AdvertisementData]:
    print(f"Scanning up to {timeout:.0f}s for {name_filter or NAME_PREFIX + '*'} ...")
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    matches = [(d, a) for d, a in found.values() if _is_petkit(d, a, name_filter)]
    if not matches:
        raise SystemExit("No PetKit fountain found. Is it in range and is the PetKit app closed?")
    matches.sort(key=lambda m: m[1].rssi, reverse=True)
    if len(matches) > 1:
        print("Several fountains found, using the strongest. Narrow with --name.")
    return matches[0]


class Session:
    """One BLE connection with raw frame logging."""

    def __init__(self, client: BleakClient, log_path: Path | None, pad: bool) -> None:
        self.client = client
        self._asm = pf.FrameAssembler()
        self._queue: asyncio.Queue[pf.Frame] = asyncio.Queue()
        self._seq = 0
        self._pad = pad
        self.redact: bytes | None = None
        self._log = log_path.open("a") if log_path else None

    def _record(self, direction: str, raw: bytes, frame: pf.Frame | None = None) -> None:
        stamp = datetime.now().isoformat(timespec="milliseconds")
        label = f"{frame.name}({frame.cmd}) type={frame.type} seq={frame.seq}" if frame else "chunk"
        shown = raw.hex()
        if self.redact:  # keep the pairing secret off the screen; the capture file stays raw
            shown = shown.replace(self.redact.hex(), "<secret>")
        print(f"  {direction} {label}: {shown}")
        if self._log:
            entry = {"t": stamp, "dir": direction, "hex": raw.hex()}
            if frame:
                entry |= {"cmd": frame.cmd, "type": frame.type, "seq": frame.seq, "payload": frame.payload.hex()}
            self._log.write(json.dumps(entry) + "\n")
            self._log.flush()

    def _on_notify(self, _char: object, data: bytearray) -> None:
        self._record("RX", bytes(data))  # verbatim notification, before reassembly
        for frame in self._asm.feed(bytes(data)):
            if frame.raw[7] != 0:
                print(f"     note: reserved byte 7 is 0x{frame.raw[7]:02x}, not 00")
            print(f"     frame {frame.name}({frame.cmd}) type={frame.type} seq={frame.seq} len={len(frame.payload)}")
            self._queue.put_nowait(frame)
        if self._asm.dropped:
            print(f"     !! discarded bytes that are not a frame: {self._asm.dropped.hex()}")
            self._asm.dropped.clear()

    async def start(self) -> None:
        await self.client.start_notify(pf.NOTIFY_UUID, self._on_notify)
        await asyncio.sleep(0.5)

    async def request(
        self, cmd: int, payload: bytes = b"", *, timeout: float = 5.0, allow_write: bool = False
    ) -> pf.Frame | None:
        """Send one request and wait for the reply with the same cmd byte."""
        if cmd not in pf.READ_ONLY_CMDS and not allow_write:
            raise RuntimeError(f"refusing to send CMD {cmd}: not on the read-only list")
        if self._pad and cmd != pf.CMD_SET_TIME:
            payload = b"\x00\x00" + payload  # legacy PetkitW5BLEMQTT / PR #203 framing
        frame = pf.Frame(cmd, pf.TYPE_REQUEST, self._seq, payload)
        raw = pf.build_frame(cmd, pf.TYPE_REQUEST, self._seq, payload)
        self._seq = (self._seq + 1) & 0xFF
        self._record("TX", raw, frame)
        await self.client.write_gatt_char(pf.WRITE_UUID, raw, response=False)
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            try:
                reply = await asyncio.wait_for(self._queue.get(), left)
            except TimeoutError:
                break
            if reply.cmd == cmd:
                _show(reply)
                return reply
            _show(reply, unsolicited=True)
        print(f"  !! no reply to CMD {cmd} within {timeout:.0f}s")
        return None

    async def drain(self, seconds: float) -> None:
        """Print unsolicited frames (e.g. CMD 230 pushes) for a while."""
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            try:
                _show(await asyncio.wait_for(self._queue.get(), left), unsolicited=True)
            except TimeoutError:
                break

    def close(self) -> None:
        if self._log:
            self._log.close()


def _show(frame: pf.Frame, *, unsolicited: bool = False) -> None:
    decoded = pf.decode(frame)
    tag = "unsolicited " if unsolicited else ""
    if decoded is not None:
        print(f"     {tag}{frame.name}: {json.dumps(decoded)}")
    elif unsolicited:
        print(f"     {tag}{frame.name}: {len(frame.payload)} bytes, not decoded yet")


async def _dump_gatt(client: BleakClient) -> None:
    print("GATT table:")
    for service in client.services:
        print(f"  service {service.uuid}")
        for char in service.characteristics:
            print(f"    char {char.uuid}  [{','.join(char.properties)}]")


def _log_path(args: argparse.Namespace) -> Path | None:
    if args.no_log:
        return None
    folder = Path(__file__).resolve().parent.parent / "captures"
    folder.mkdir(exist_ok=True)
    return folder / f"{datetime.now():%Y%m%d-%H%M%S}-{args.command}.jsonl"


async def cmd_scan(args: argparse.Namespace) -> None:
    print(f"Scanning {args.timeout:.0f}s ...")
    found = await BleakScanner.discover(timeout=args.timeout, return_adv=True)
    matches = [(d, a) for d, a in found.values() if _is_petkit(d, a, args.name)]
    print(f"{len(found)} BLE devices seen, {len(matches)} PetKit match(es).")
    for dev, adv in sorted(matches, key=lambda m: m[1].rssi, reverse=True):
        _print_adv(dev, adv)
    if not matches:
        print("No Petkit_* name seen. Named devices in range (macOS shows no MAC to match on):")
        for dev, adv in sorted(found.values(), key=lambda m: m[1].rssi, reverse=True):
            if adv.local_name or dev.name:
                _print_adv(dev, adv)


async def _open(args: argparse.Namespace):
    dev, adv = await _find(args.name, args.timeout)
    _print_adv(dev, adv)
    log = _log_path(args)
    if log:
        print(f"Raw frames -> {log}")
    client = BleakClient(dev, timeout=20.0)
    await client.connect()
    print(f"Connected, MTU {client.mtu_size}")
    session = Session(client, log, pad=args.pad)
    return client, session


async def cmd_probe(args: argparse.Namespace) -> None:
    """Connect, dump GATT, send CMD 213 only. No auth, no writes."""
    client, session = await _open(args)
    try:
        await _dump_gatt(client)
        await session.start()
        info = await session.request(pf.CMD_DEVICE_INFO)
        if info:
            print("Secret candidates the reference projects would try (nothing sent):")
            for name, value in pf.secret_candidates(info.payload).items():
                print(f"  {name:9s} {value.hex()}")
        await session.drain(args.linger)
    finally:
        session.close()
        await client.disconnect()


async def _authenticate(session: Session, args: argparse.Namespace) -> bool:
    info = await session.request(pf.CMD_DEVICE_INFO)
    if not info:
        return False
    secret = pf.parse_secret_arg(args.secret, info.payload, pad_right=args.secret_pad == "right")
    named = args.secret in pf.secret_candidates(info.payload)
    session.redact = None if named else secret
    print(f"Verifying secret {secret.hex() if named else '<hidden>'} with CMD 86 (read-only check)")
    await asyncio.sleep(0.3)
    reply = await session.request(pf.CMD_VERIFY, secret)
    ok = bool(reply and reply.payload and reply.payload[0] == 1)
    print("  => secret ACCEPTED" if ok else "  => secret REJECTED (or no reply)")
    if ok and args.set_time:
        sec = int(time.time()) - PETKIT_EPOCH
        offset_hours = round(datetime.now().astimezone().utcoffset().total_seconds() / 3600)
        payload = bytes([0]) + sec.to_bytes(4, "big") + bytes([offset_hours + 12])
        print(f"Sending CMD 84 clock sync (UTC{offset_hours:+d}) because --set-time was given")
        await asyncio.sleep(0.3)
        await session.request(pf.CMD_SET_TIME, payload, allow_write=True)
    return ok


async def cmd_status(args: argparse.Namespace) -> None:
    client, session = await _open(args)
    try:
        await session.start()
        if not await _authenticate(session, args):
            return
        for cmd, payload in (
            (pf.CMD_FIRMWARE, b""),
            (pf.CMD_STATE, b""),
            (pf.CMD_CONFIG, b""),
            (pf.CMD_BATTERY, b"\x00\x00"),
        ):
            await asyncio.sleep(0.3)
            if not client.is_connected:
                print("  !! fountain disconnected")
                return
            await session.request(cmd, payload, timeout=3.0 if cmd == pf.CMD_CONFIG else 5.0)
        await session.drain(args.linger)
    finally:
        session.close()
        if client.is_connected:
            await client.disconnect()


async def cmd_listen(args: argparse.Namespace) -> None:
    """Stay connected, poll CMD 210 and print every change and every push."""
    client, session = await _open(args)
    try:
        await session.start()
        if not await _authenticate(session, args):
            return
        print(f"Listening {args.seconds:.0f}s, polling state every {args.interval:.0f}s. Ctrl+C to stop.")
        end = time.monotonic() + args.seconds
        previous: bytes | None = None
        while time.monotonic() < end and client.is_connected:
            reply = await session.request(pf.CMD_STATE)
            if reply and previous is not None and reply.payload != previous:
                diff = [
                    f"[{i}] {a:02x}->{b:02x}"
                    for i, (a, b) in enumerate(zip(previous, reply.payload, strict=False))
                    if a != b
                ]
                print(f"  ** state changed: {' '.join(diff)}")
            if reply:
                previous = reply.payload
            await session.drain(args.interval)
    finally:
        session.close()
        if client.is_connected:
            await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", help="substring of the BLE name (default: any Petkit_*)")
    parser.add_argument("--timeout", type=float, default=10.0, help="scan timeout, seconds")
    parser.add_argument("--no-log", action="store_true", help="do not write captures/*.jsonl")
    parser.add_argument("--pad", action="store_true", help="prefix request data with 00 00 (legacy framing)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="list PetKit advertisements")

    probe = sub.add_parser("probe", help="GATT dump + CMD 213, no auth")
    probe.add_argument("--linger", type=float, default=5.0, help="seconds to wait for pushes")

    for name, text in (("status", "auth with CMD 86 and read state once"), ("listen", "auth and watch state/pushes")):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("--secret", required=True, help="hex (up to 16 digits) or zero|leet|derived6|derived8")
        cmd.add_argument(
            "--secret-pad", choices=("left", "right"), default="left", help="zero-pad side for a short hex secret"
        )
        cmd.add_argument("--set-time", action="store_true", help="also send CMD 84 clock sync (a write)")
        if name == "status":
            cmd.add_argument("--linger", type=float, default=10.0, help="seconds to wait for pushes")
        else:
            cmd.add_argument("--seconds", type=float, default=300.0)
            cmd.add_argument("--interval", type=float, default=5.0)

    args = parser.parse_args()
    if getattr(args, "secret", None):
        try:  # fail on a malformed secret before touching the fountain
            pf.parse_secret_arg(args.secret, bytes(8))
        except ValueError as err:
            parser.error(f"--secret: {err}")
    handler = {"scan": cmd_scan, "probe": cmd_probe, "status": cmd_status, "listen": cmd_listen}[args.command]
    try:
        asyncio.run(handler(args))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
