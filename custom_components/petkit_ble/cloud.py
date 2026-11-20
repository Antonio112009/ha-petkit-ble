"""Read a fountain's BLE secret from the PetKit cloud integration, if present.

The PetKit cloud assigns each fountain a secret when it is bound to an
account, and the fountain only accepts BLE commands after that secret is
verified (CMD 86). The cloud integration (``petkit`` domain) already holds
the device list in memory, so the secret can be read from there without a
second PetKit login, which would sign other sessions out.

Nothing here imports the cloud integration: it only looks at objects that
integration left on its config entries, and returns ``None`` when they are
missing or shaped differently.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .const import CLOUD_DOMAIN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


def normalize_mac(value: Any) -> str:
    """Lower-case hex digits of a MAC, without separators."""
    return "".join(ch for ch in str(value or "").lower() if ch in "0123456789abcdef")


def match_cloud_secret(devices: Any, address: str, device_id: int) -> str | None:
    """Pick the secret of the cloud device matching this fountain.

    A device matches on its MAC address or, failing that, on the numeric id
    the fountain reports over BLE (CMD 213), which is the cloud device id.
    """
    wanted_mac = normalize_mac(address)
    for device in devices:
        secret = getattr(device, "secret", None)
        if not secret or not isinstance(secret, str):
            continue
        same_mac = bool(wanted_mac) and normalize_mac(getattr(device, "mac", None)) == wanted_mac
        same_id = bool(device_id) and getattr(device, "id", None) == device_id
        if same_mac or same_id:
            return secret
    return None


def find_cloud_secret(hass: HomeAssistant, address: str, device_id: int) -> str | None:
    """Return the cloud secret for this fountain, or ``None`` when unavailable."""
    for entry in hass.config_entries.async_entries(CLOUD_DOMAIN):
        client = getattr(getattr(entry, "runtime_data", None), "client", None)
        entities = getattr(client, "petkit_entities", None)
        if not isinstance(entities, dict):
            continue
        secret = match_cloud_secret(entities.values(), address, device_id)
        if secret:
            _LOGGER.debug("Found a BLE secret for %s in the PetKit cloud integration", address)
            return secret
    return None
