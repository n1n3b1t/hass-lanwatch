from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

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


@dataclass
class DeviceInfo:
    ip: str
    name: str
    mac: str
    last_seen: datetime


class LanwatchCoordinator(DataUpdateCoordinator[dict[str, DeviceInfo]]):
    def __init__(
        self, hass: HomeAssistant, subnets: list[str], interval_s: int, absent_after_s: int
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

    async def _async_update_data(self) -> dict[str, DeviceInfo]:
        return await self.hass.async_add_executor_job(self._scan_once)

    def _rev_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:  # noqa: BLE001
            return ""

    def _scan_once(self) -> dict[str, DeviceInfo]:
        from netaddr import IPNetwork  # local import
        from scapy.all import arping, conf  # type: ignore

        conf.verb = 0
        hits: dict[str, str] = {}
        for net in self._subnets:
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

        now = datetime.utcnow()
        for mac, ip in hits.items():
            name = self._rev_dns(ip)
            self._seen[mac] = DeviceInfo(ip=ip, name=name, mac=mac, last_seen=now)

        cutoff = now - self._absent_after
        for mac, info in list(self._seen.items()):
            if info.last_seen < cutoff and mac not in hits:
                # keep entry but state will be away in platform
                pass
        return self._seen


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    subnets: list[str] = entry.data.get(CONF_SUBNETS, ["192.168.1.0/24"])
    interval: int = entry.data.get(CONF_INTERVAL, DEFAULT_INTERVAL)
    absent_after: int = entry.data.get(CONF_ABSENT_AFTER, DEFAULT_ABSENT_AFTER)

    coordinator = LanwatchCoordinator(hass, subnets, interval, absent_after)
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