from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import DOMAIN, LanwatchCoordinator


async def async_setup_entry(
    hass: HomeAssistant, 
    entry: ConfigEntry, 
    async_add_entities: AddEntitiesCallback
) -> None:
    """Set up device tracker entities."""
    coordinator: LanwatchCoordinator = hass.data[DOMAIN][entry.entry_id]
    
    # Create entities for all devices already in storage
    entities = []
    for mac in coordinator.data.keys():
        entities.append(LanwatchTracker(coordinator, mac))
    
    if entities:
        async_add_entities(entities)
    
    # Set up listener for new devices
    @callback
    def _check_for_new_devices() -> None:
        """Check for new devices after coordinator update."""
        new_macs = coordinator.get_new_devices()
        if new_macs:
            new_entities = [LanwatchTracker(coordinator, mac) for mac in new_macs]
            async_add_entities(new_entities)
    
    # Register the listener
    entry.async_on_unload(
        coordinator.async_add_listener(_check_for_new_devices)
    )


class LanwatchTracker(CoordinatorEntity[LanwatchCoordinator], TrackerEntity):
    """Representation of a LanWatch device tracker."""
    
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, coordinator: LanwatchCoordinator, mac: str) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        self._mac = mac.upper()
        self._absent_after = coordinator._absent_after  # noqa: SLF001
        
        # Create a clean device ID
        mac_clean = mac.lower().replace(":", "")
        self._attr_unique_id = f"lanwatch_{mac_clean}"
        
        # Set initial name based on device info if available
        device_info = coordinator.data.get(mac)
        if device_info and device_info.name:
            # Use hostname if available
            self._attr_name = device_info.name.split(".")[0]  # Remove domain part
        else:
            # Use last 5 chars of MAC for name
            self._attr_name = f"Device {mac[-5:].replace(':', '')}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        info = self.coordinator.data.get(self._mac)
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=self._attr_name,
            manufacturer=info.vendor if info and info.vendor else None,
            model="Network Device",
            connections={("mac", self._mac)},
        )

    @property
    def source_type(self) -> str:
        """Return the source type."""
        return "router"

    @property
    def is_connected(self) -> bool:
        """Return true if device is connected to network."""
        info = self.coordinator.data.get(self._mac)
        if not info:
            return False
        
        # Check if device was seen recently
        time_since = dt_util.utcnow() - info.last_seen
        return time_since < self._absent_after

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        info = self.coordinator.data.get(self._mac)
        return info.ip if info else None

    @property
    def mac_address(self) -> str | None:
        """Return the mac address of the device."""
        return self._mac

    @property
    def hostname(self) -> str | None:
        """Return hostname of the device."""
        info = self.coordinator.data.get(self._mac)
        return info.name if info and info.name else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        info = self.coordinator.data.get(self._mac)
        if not info:
            return {}
        
        attrs = {
            "mac": self._mac,
            "ip": info.ip,
            "last_seen": info.last_seen.isoformat(),
        }
        
        if info.name:
            attrs["hostname"] = info.name
        
        if info.vendor:
            attrs["vendor"] = info.vendor
        
        # Calculate time since last seen
        time_since = dt_util.utcnow() - info.last_seen
        attrs["last_seen_seconds_ago"] = int(time_since.total_seconds())
        
        return attrs

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # Update name if hostname becomes available
        info = self.coordinator.data.get(self._mac)
        if info and info.name and not self._attr_name.startswith("Device "):
            # Don't override a meaningful name with a generic one
            pass
        elif info and info.name:
            self._attr_name = info.name.split(".")[0]
        
        self.async_write_ha_state()