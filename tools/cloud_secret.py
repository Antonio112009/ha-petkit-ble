# /// script
# requires-python = ">=3.11"
# dependencies = ["pypetkitapi>=1.31.1", "aiohttp"]
# ///
"""Print what the PetKit cloud knows about your fountain's BLE pairing.

    uv run tools/cloud_secret.py --region NL --timezone Europe/Amsterdam

Read-only: it logs in and lists devices. It asks for the password on the
terminal and stores nothing. Note that PetKit allows one session per account,
so logging in here can sign the phone app out; use the same account Home
Assistant already uses if that is a secondary/family account.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path

import aiohttp
from pypetkitapi import PetKitClient
from pypetkitapi.water_fountain_container import WaterFountain

sys.path.insert(0, str(Path(__file__).resolve().parent))

import petkit_frames as pf


async def run(args: argparse.Namespace) -> None:
    username = args.username or input("PetKit account (email/phone): ").strip()
    password = getpass.getpass("PetKit password (not echoed, not stored): ")
    async with aiohttp.ClientSession() as http:
        client = PetKitClient(username, password, args.region, args.timezone, http)
        await client.get_devices_data()
        fountains = [e for e in client.petkit_entities.values() if isinstance(e, WaterFountain)]
        if not fountains:
            print("No water fountain on this account.")
            return
        for f in fountains:
            print(f"\n{f.name}")
            print(f"  cloud id : {f.id}  (hex BE {f.id.to_bytes(8, 'big').hex()})")
            print(f"  mac      : {f.mac}")
            print(f"  sn       : {f.sn}")
            print(f"  firmware : {f.firmware}  hardware: {f.hardware}")
            print(f"  secret   : {f.secret!r}")
            if not f.secret:
                print("  -> the cloud returned no secret for this device")
                continue
            id_be = f.id.to_bytes(8, "big")
            guesses = {
                "derived from id (8 bytes BE)": pf.derive_secret(id_be).hex(),
                "derived from id (stripped)": pf.derive_secret(id_be.lstrip(b"\x00")).hex(),
                "leet (zero id)": pf.derive_secret(bytes(6)).hex(),
            }
            norm = f.secret.lower().rjust(16, "0")  # padding side unconfirmed
            for label, value in guesses.items():
                print(f"  {label:30s} {value}  {'== cloud secret' if value == norm else ''}")
            print(f"  secret length: {len(f.secret)} chars (16 = 8 bytes, no padding question)")
            print(f"  try: uv run tools/petkit_cli.py status --secret {f.secret}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username")
    parser.add_argument("--region", required=True, help="country code of the account, e.g. NL, GB, DE")
    parser.add_argument("--timezone", required=True, help="e.g. Europe/Amsterdam")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
