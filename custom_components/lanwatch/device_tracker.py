from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import DOMAIN, LanwatchCoordinator
from . import DeviceInfo as LanwatchDeviceInfo

_LOGGER = logging.getLogger(__name__)


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
        _LOGGER.info("Creating %d initial device tracker entities", len(entities))
        async_add_entities(entities)
    else:
        _LOGGER.info("No initial devices found, waiting for first scan")
    
    # Set up listener for new devices
    @callback
    def _check_for_new_devices() -> None:
        """Check for new devices after coordinator update."""
        new_macs = coordinator.get_new_devices()
        if new_macs:
            _LOGGER.info("Creating entities for %d new devices", len(new_macs))
            new_entities = [LanwatchTracker(coordinator, mac) for mac in new_macs]
            async_add_entities(new_entities)
    
    # Register the listener
    entry.async_on_unload(
        coordinator.async_add_listener(_check_for_new_devices)
    )


class LanwatchTracker(CoordinatorEntity[LanwatchCoordinator], ScannerEntity):
    """Representation of a LanWatch device tracker."""
    
    _attr_should_poll = False
    _attr_has_entity_name = False

    def __init__(self, coordinator: LanwatchCoordinator, mac: str) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        # Ensure MAC is uppercase for consistency
        self._mac = mac.upper()
        self._absent_after = coordinator._absent_after  # noqa: SLF001
        
        # Create a clean device ID
        mac_clean = self._mac.lower().replace(":", "")
        self._attr_unique_id = f"lanwatch_{mac_clean}"
        
        # Set initial name based on device info if available
        device_info = coordinator.data.get(self._mac)  # Use uppercase MAC
        self._attr_name = self._generate_device_name(device_info)
        
        _LOGGER.debug("Created device tracker for MAC=%s, name=%s", self._mac, self._attr_name)
    
    def _generate_device_name(self, device_info: LanwatchDeviceInfo | None) -> str:
        """Generate a meaningful device name from available information."""
        if not device_info:
            return f"Unknown {self._mac[-8:].replace(':', '')}"
        
        # Use DHCP hostname if available
        if device_info.dhcp_info and device_info.dhcp_info.get("hostname"):
            hostname = device_info.dhcp_info["hostname"]
            # Clean up hostname
            clean_name = hostname.replace("-", " ").replace("_", " ")
            # Handle special cases
            if "Valentins" in clean_name:
                clean_name = clean_name.replace("Valentins", "Valentin's")
            return clean_name.title()
        
        # Check for special mDNS services first
        if device_info.mdns_services:
            services = device_info.mdns_services
            
            # ESPHome devices
            if "_esphomelib._tcp" in services:
                esphome_name = services["_esphomelib._tcp"]
                return esphome_name.title()
            
            # Google Cast devices (Chromecast, Android TV)
            if "_googlecast._tcp" in services:
                cast_name = services["_googlecast._tcp"]
                # Extract friendly name from service name
                if "BRAVIA" in cast_name or "SONY" in cast_name:
                    return "Sony TV"
                elif cast_name:
                    return cast_name.replace("-", " ").title()
            
            # Apple devices
            if "_companion-link._tcp" in services:
                companion_name = services["_companion-link._tcp"]
                # Clean up Apple device names
                if "iPad" in companion_name:
                    return companion_name.replace("___", "'")
                elif "iPhone" in companion_name:
                    return companion_name.replace("___", "'")
                elif "MacBook" in companion_name:
                    return companion_name.replace("___", "'")
        
        # Priority 1: Use hostname if available and valid
        if device_info.name:
            hostname = device_info.name.split(".")[0]
            
            # Special handling for known patterns
            if "Android" in hostname and device_info.mdns_services:
                # Android TV or device - try to get better name from services
                if "_googlecast._tcp" in device_info.mdns_services:
                    return "Android TV"
                elif "_androidtvremote2._tcp" in device_info.mdns_services:
                    return "Android TV"
                else:
                    return "Android Device"
            
            # iPad/iPhone names
            if "iPad" in hostname or "iPhone" in hostname:
                # Clean up Apple device names (iPad-Valentin -> iPad Valentin)
                clean_name = hostname.replace("-", " ")
                return clean_name
            
            # Check if it's a real hostname (not IP or localhost)
            if (hostname and 
                not hostname.replace(".", "").replace("-", "").isdigit() and
                hostname.lower() not in ["localhost", "unknown", "_gateway", "android"]):
                # Clean up hostname
                clean_name = hostname.replace("-", " ").replace("_", " ")
                # Handle special cases
                if "Valentins" in clean_name:
                    clean_name = clean_name.replace("Valentins", "Valentin's")
                # Remove common suffixes
                for suffix in [".lan", ".local", ".home", ".localdomain"]:
                    clean_name = clean_name.replace(suffix, "")
                return clean_name.title()
        
        # Priority 2: Use vendor + device type if vendor is known
        if device_info.vendor:
            vendor_name = device_info.vendor.split()[0]  # Take first word of vendor
            # Try to guess device type from vendor
            vendor_lower = device_info.vendor.lower()
            if "apple" in vendor_lower:
                if self._mac.startswith(("00:17:F2", "00:1B:63", "00:1E:C2")):
                    return f"{vendor_name} TV"
                elif self._mac.startswith(("F0:18:98", "F0:99:BF")):
                    return f"{vendor_name} Watch"
                else:
                    return f"{vendor_name} Device"
            elif "samsung" in vendor_lower:
                # Check if it's a phone (Galaxy series)
                if self._mac.startswith(("A0:AF:BD", "B0:A4:60", "E8:50:8B")):
                    return "Samsung Phone"
                elif self._mac.startswith(("00:16:32", "00:1D:F6")):
                    return "Samsung TV"
                else:
                    return f"Samsung {self._mac[-5:].replace(':', '')}"
            elif "amazon" in vendor_lower:
                return f"Echo {self._mac[-5:].replace(':', '')}"
            elif "google" in vendor_lower:
                return f"Google {self._mac[-5:].replace(':', '')}"
            elif "espressif" in vendor_lower:
                # ESP32/ESP8266 devices
                return f"IoT Device {self._mac[-5:].replace(':', '')}"
            elif "sonos" in vendor_lower:
                return "Sonos Speaker"
            elif "roku" in vendor_lower:
                return "Roku Device"
            elif "nest" in vendor_lower:
                return "Nest Device"
            elif "ring" in vendor_lower:
                return "Ring Device"
            elif any(tv in vendor_lower for tv in ["lg", "sony", "vizio", "tcl"]):
                return f"{vendor_name} TV"
            else:
                # Generic vendor device
                return f"{vendor_name} {self._mac[-5:].replace(':', '')}"
        
        # Priority 3: Use MAC address suffix
        return f"Device {self._mac[-8:].replace(':', '')}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        info = self.coordinator.data.get(self._mac)
        
        # Use the same name generation logic
        device_name = self._generate_device_name(info)
        
        # Determine manufacturer
        manufacturer = "Unknown"
        if info and info.vendor:
            # Clean up vendor name
            manufacturer = info.vendor.split("(")[0].strip()
        
        # Determine model based on device type and OS
        model = "Network Device"
        if info:
            if info.device_type and info.os_hint:
                model = f"{info.device_type.replace('_', ' ').title()} ({info.os_hint})"
            elif info.device_type:
                model = info.device_type.replace('_', ' ').title()
            elif info.os_hint:
                model = f"Device ({info.os_hint})"
        
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=device_name,
            manufacturer=manufacturer,
            model=model,
            connections={("mac", self._mac)},
            sw_version=info.ip if info else None,
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
            
        if info.device_type:
            attrs["device_type"] = info.device_type
            
        if info.os_hint:
            attrs["os"] = info.os_hint
            
        if info.open_ports:
            attrs["open_ports"] = info.open_ports
            
        if info.capabilities:
            attrs["capabilities"] = info.capabilities
            
        if info.dhcp_info:
            if "hostname" in info.dhcp_info:
                attrs["dhcp_hostname"] = info.dhcp_info["hostname"]
            if "vendor_class_id" in info.dhcp_info:
                attrs["dhcp_vendor_class"] = info.dhcp_info["vendor_class_id"]
                
        if info.mdns_services:
            # Add a simplified list of mDNS service types
            service_types = list(info.mdns_services.keys())
            if service_types:
                attrs["mdns_services"] = service_types
        
        # Calculate time since last seen
        time_since = dt_util.utcnow() - info.last_seen
        attrs["last_seen_seconds_ago"] = int(time_since.total_seconds())
        
        return attrs

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        info = self.coordinator.data.get(self._mac)
        new_name = self._generate_device_name(info)
        
        # Update name if we found better information
        if new_name != self._attr_name:
            # Only update if the new name is more specific
            if ("Unknown" in self._attr_name or 
                "Device" in self._attr_name and self._mac[-8:].replace(':', '') in self._attr_name):
                old_name = self._attr_name
                self._attr_name = new_name
                _LOGGER.info("Updated device name for %s: %s -> %s", self._mac, old_name, new_name)
        
        self.async_write_ha_state()