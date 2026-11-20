# PetKit fountain BLE protocol

What this integration speaks over Bluetooth LE. Everything marked **verified**
was captured on a PetKit Eversweet Max Cordless (identifiers below are replaced with dummies) (BLE name `Petkit_CTW3UV`,
type CTW3, firmware 111, hardware 1) bound to a PetKit account, using
`tools/petkit_cli.py`. The rest comes from the reference projects
(`aavdberg/ha-petkit`, `phldgmn/ha-petkit-ble`, `Jezza34000/homeassistant_petkit` PR #203)
and is marked **unverified**.

## Advertisement (verified)

| Field | Value | Meaning |
|---|---|---|
| Local name | `Petkit_CTW3UV` | `Petkit_<MODEL>`; other units append `_<NNN>` |
| Service UUID | `5b70bdd8-91bf-e789-9f4d-720508e63ebb` | Advertised only; not in the GATT table |
| Service data `0xC1A4` | `38 aa bb cc 00 f8` | UUID + first 4 bytes = MAC `A4:C1:38:AA:BB:CC` |
| Service data `0x0000` | `17 a1 b2 c3` | Device id, big-endian (= cloud device id) |

The MAC in the service data lets a macOS client, which never sees the real
address, identify a fountain.

## GATT (verified)

One service, `0000aaa0-0000-1000-8000-00805f9b34fb`:

| Characteristic | Properties | Use |
|---|---|---|
| `0000aaa2-…` | write, write-without-response | Requests |
| `0000aaa1-…` | read, notify | Replies and pushes |

There is no Device Information Service. MTU negotiated at 158, so every frame
seen so far fits one notification; the parser still reassembles split frames.
The fountain accepts **one** connection at a time.

## Frame (verified)

```
FA FC FD | cmd | type | seq | len | 00 | payload (len bytes) | FB
```

- `type`: `1` request, `2` response.
- `seq`: per-connection counter starting at 0; the response echoes it.
- `len`: payload length, one byte. Byte 7 was `00` in every frame.
- No checksum.
- Requests carry a bare payload. The legacy `00 00` prefix used by
  PetkitW5BLEMQTT is not needed on CTW3.

Example, CMD 213 request and reply:

```
TX fa fc fd d5 01 00 00 00 fb
RX fa fc fd d5 02 00 16 00 | 00 00 00 00 17 a1 b2 c3 | "20260101W00001" | fb
```

## Session and the secret (verified)

A fountain bound to an account answers data commands only after its secret
is verified:

1. `CMD 213` get device info: 8-byte device id (big-endian) + ASCII serial.
   A zero id means the fountain is not bound.
2. `CMD 86` verify secret: 8 bytes. Reply `01` accepted, `00` rejected.
3. Read commands.

**Where the secret comes from.** The PetKit cloud assigns it at binding time
and returns it as the fountain's `secret` field (12 hex characters, 6 bytes).
The fountain accepts it **left-padded with zeros to 8 bytes**. It is not
derivable: the id-reversal formula from PetkitW5BLEMQTT / PR #203
(`00 00 c3 b2 a1 17 0d 25` for this unit) is rejected.

**Coexistence with the app.** `CMD 86` only verifies, so reading the secret
from the cloud and verifying it leaves the app binding untouched. `CMD 73`
(init) writes a new id + secret; after it the app and the cloud relay can no
longer authenticate until the fountain is factory reset and bound again. The
integration sends `CMD 73` only when the user explicitly picks "Re-pair".

An unbound fountain (id 0) accepts the all-zero secret (unverified here).

`CMD 84` (clock sync) is **not** required before reads (verified). The
integration still sends it after auth so the fountain's "today" counters and
schedules follow local time.

## Commands

| CMD | Name | Request payload | Reply payload | Status |
|---|---|---|---|---|
| 213 | Device info | empty | id (8, BE) + serial (ASCII) | verified |
| 86 | Verify secret | secret (8) | `01` ok / `00` rejected | verified |
| 200 | Firmware | empty | hw, fw, + 15 bytes | verified |
| 210 | State | empty | see below | verified |
| 211 | Settings | empty | see below | verified |
| 66 | Battery | `00 00` | mV (2, BE) + percent | verified |
| 84 | Set clock | `00` + seconds since 2000-01-01 UTC (4, BE) + (UTC offset hours + 12) | `01` | unverified |
| 73 | Init (destructive) | id (8, BE) + secret (8) | `01` | unverified |
| 220 | Set power / mode | CTW3: `power, suspend, mode`; others: `power, mode` | | unverified |
| 221 | Write settings | same layout as the 211 reply | | unverified |
| 222 | Reset filter | empty | | unverified |
| 230 | State push | device initiated, state + settings | | not seen yet |

### CMD 200 reply (CTW3, 17 bytes)

`01 6f 02 00 02 00 09 02 05 02 01 00 00 04 03 02 01`: byte 0 hardware (1),
byte 1 firmware (111). The rest is undecoded.

### CMD 210 reply (CTW3, 30 bytes)

Captured: `01 01 02 02 00 00 00 00 00 00 00 c6 9e 62 00 00 00 70 77 00 14 3d 10 82 64 00 26 04 90 04`

| Byte | Field | Captured | Notes |
|---|---|---|---|
| 0 | power | 1 | |
| 1 | suspend | 1 | 1 = running, 0 = paused |
| 2 | mode | 2 | 1 normal, 2 smart |
| 3 | electric status | 2 | 2 = on mains |
| 4 | do-not-disturb active | 0 | |
| 5 | breakdown warning | 0 | exposed as "error code" |
| 6 | water missing | 0 | |
| 7 | low battery | 0 | |
| 8 | filter warning | 0 | |
| 9-12 | pump runtime, s (BE) | 50846 | |
| 13 | filter % | 98 | |
| 14 | pump running | 0 | |
| 15-18 | pump runtime today, s (BE) | 28791 | depends on the device clock |
| 19 | pet detected | 0 | `02` while a pet is detected (aavdberg #65) |
| 20-21 | supply mV (BE) | 5181 | |
| 22-23 | battery mV (BE) | 4226 | |
| 24 | battery % | 100 | |
| 25 | module status | 0 | |
| 26-29 | undecoded | `26 04 90 04` | |

W4 / W5 / CTW2 answer 12 to 18 bytes with a different layout (unverified):
power, mode, dnd, breakdown, water missing, filter warning, runtime (4),
filter %, running, runtime today (4), smart on, smart off.

### CMD 211 reply (CTW3, 12 bytes)

Captured: `03 03 00 19 0e 10 01 02 00 00 00 00`

| Byte | Field | Captured |
|---|---|---|
| 0 | smart mode work, min | 3 |
| 1 | smart mode sleep, min | 3 |
| 2-3 | on-battery work, s (BE) | 25 |
| 4-5 | on-battery sleep, s (BE) | 3600 |
| 6 | LED on | 1 |
| 7 | LED brightness (1-3) | 2 |
| 8 | do-not-disturb enabled | 0 |
| 9 | child lock | 0 |
| 10 | smart-mode pet detection | 0 |
| 11 | battery-mode pet detection | 0 |

Firmware 111 does answer CMD 211, contrary to the aavdberg notes.

### CMD 66 reply (CTW3, 3 bytes)

`10 88 64`: 4232 mV big-endian, 100 %.

## Drink events

No drink counter or drink log has been found in the BLE protocol. The only
signal is byte 19 of the state, sampled at poll time, so a drink shorter than
the poll interval can be missed. Whether `CMD 230` pushes carry drink records
is open: none arrived during a 10 second window.

## Capturing more

```
uv run tools/petkit_cli.py scan
uv run tools/petkit_cli.py probe
uv run tools/petkit_cli.py status --secret "$(cat captures/secret.txt)"
uv run tools/petkit_cli.py listen --secret "$(cat captures/secret.txt)" --seconds 600
```

The CLI cannot send CMD 73 or any settings write. Raw notifications are
appended to `captures/*.jsonl` (git-ignored; they contain the secret and the
serial number).
