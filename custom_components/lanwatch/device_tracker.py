from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DOMAIN, LanwatchCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    coordinator: LanwatchCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = [LanwatchTracker(coordinator, mac) for mac in coordinator.data.keys()]

    async_add_entities(entities)


class LanwatchTracker(CoordinatorEntity[LanwatchCoordinator], TrackerEntity):
    _attr_should_poll = False
    _attr_source_type = "router"

    def __init__(self, coordinator: LanwatchCoordinator, mac: str) -> None:
        super().__init__(coordinator)
        self._mac = mac
        self._absent_after = coordinator._absent_after  # noqa: SLF001
        self._attr_name = f"LAN {mac[-5:].replace(':','')}"
        self._attr_unique_id = f"lan_{mac.lower().replace(':','')}"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.unique_id)},
            name=self.name,
        )

    @property
    def is_connected(self) -> bool:
        info = self.coordinator.data.get(self._mac)
        if not info:
            return False
        return (datetime.utcnow() - info.last_seen) < self._absent_after

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self.coordinator.data.get(self._mac)
        if not info:
            return {}
        return {
            "ip": info.ip,
            "hostname": info.name,
            "mac": self._mac,
            "last_seen": info.last_seen.isoformat(),
        }

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._handle_coordinator_update))

    def _handle_coordinator_update(self) -> None:
        # Add new entities for newly seen MACs
        if self._mac not in self.coordinator.data:
            self.async_write_ha_state()
            return
        self.async_write_ha_state() 