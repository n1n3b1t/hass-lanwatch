from __future__ import annotations

import logging
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    CONF_ABSENT_AFTER,
    CONF_INTERVAL,
    CONF_SUBNETS,
    DEFAULT_ABSENT_AFTER,
    DEFAULT_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.DEVICE_TRACKER]
STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}_devices"


@dataclass
class DeviceInfo:
    ip: str
    name: str
    mac: str
    last_seen: datetime
    vendor: str = ""


def perform_arp_scan(subnets: list[str]) -> dict[str, tuple[str, str]]:
    """Scan subnets using ARP and return mapping mac -> (ip, hostname)."""
    from netaddr import IPNetwork  # local import
    from scapy.all import arping, conf  # type: ignore

    conf.verb = 0
    hits: dict[str, str] = {}
    for net in subnets:
        try:
            str(IPNetwork(net))
        except Exception:  # noqa: BLE001
            continue
        try:
            ans, _ = arping(net, timeout=3, verbose=0)
            for _, r in ans:
                ip = r.psrc
                mac = getattr(r, "src_mac", None)
                if ip and mac and mac not in hits:
                    hits[mac] = ip
        except Exception:  # noqa: BLE001
            continue

    results: dict[str, tuple[str, str]] = {}
    for mac, ip in hits.items():
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:  # noqa: BLE001
            name = ""
        results[mac] = (ip, name)
    return results


class LanwatchCoordinator(DataUpdateCoordinator[dict[str, DeviceInfo]]):
    def __init__(
        self, hass: HomeAssistant, subnets: list[str], interval_s: int, absent_after_s: int, entry_id: str
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="LanWatch",
            update_interval=timedelta(seconds=interval_s),
        )
        self._subnets = subnets
        self._absent_after = timedelta(seconds=absent_after_s)
        self._seen: dict[str, DeviceInfo] = {}
        self._store = Store[dict[str, Any]](hass, STORAGE_VERSION, f"{STORAGE_KEY}_{entry_id}")
        self._new_devices: set[str] = set()

    async def async_config_entry_first_refresh(self) -> None:
        """Load stored devices before first refresh."""
        stored_data = await self._store.async_load()
        if stored_data:
            for mac, device_data in stored_data.items():
                device_data["last_seen"] = datetime.fromisoformat(device_data["last_seen"])
                self._seen[mac] = DeviceInfo(**device_data)
        await super().async_config_entry_first_refresh()

    async def _async_update_data(self) -> dict[str, DeviceInfo]:
        result = await self.hass.async_add_executor_job(self._scan_once)
        await self._save_devices()
        return result

    async def _save_devices(self) -> None:
        """Save device cache to storage."""
        data = {}
        for mac, info in self._seen.items():
            device_dict = asdict(info)
            device_dict["last_seen"] = info.last_seen.isoformat()
            data[mac] = device_dict
        await self._store.async_save(data)

    def _scan_once(self) -> dict[str, DeviceInfo]:
        pairs = perform_arp_scan(self._subnets)
        now = dt_util.utcnow()
        
        for mac, (ip, name) in pairs.items():
            if mac not in self._seen:
                self._new_devices.add(mac)
            self._seen[mac] = DeviceInfo(ip=ip, name=name or "", mac=mac, last_seen=now)

        # Don't remove devices, just mark their last_seen time
        # The device_tracker entity will handle home/away state based on last_seen
        return self._seen
    
    def get_new_devices(self) -> set[str]:
        """Get and clear the set of newly discovered devices."""
        new = self._new_devices.copy()
        self._new_devices.clear()
        return new


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    subnets: list[str] = entry.data.get(CONF_SUBNETS, ["192.168.1.0/24"])
    interval: int = entry.data.get(CONF_INTERVAL, DEFAULT_INTERVAL)
    absent_after: int = entry.data.get(CONF_ABSENT_AFTER, DEFAULT_ABSENT_AFTER)

    coordinator = LanwatchCoordinator(hass, subnets, interval, absent_after, entry.entry_id)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    async def _handle_scan_now(call) -> None:  # type: ignore[no-redef]
        await coordinator.async_request_refresh()

    hass.services.async_register(DOMAIN, "scan_now", _handle_scan_now)

    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok 