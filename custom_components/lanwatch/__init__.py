from __future__ import annotations

import logging
import socket
from dataclasses import asdict, dataclass, field
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
    mdns_services: dict = field(default_factory=dict)


def get_vendor_from_mac(mac: str) -> str:
    """Get vendor name from MAC address using OUI lookup."""
    try:
        from netaddr import EUI, NotRegisteredError
        eui = EUI(mac)
        try:
            vendor = eui.oui.registration().org
            # Clean up common vendor name patterns
            vendor = vendor.replace(" Inc.", "").replace(" Corporation", "")
            vendor = vendor.replace(" Co., Ltd.", "").replace(" Co.,Ltd.", "")
            vendor = vendor.replace(" Technology", "").replace(" Electronics", "")
            return vendor
        except NotRegisteredError:
            return ""
    except Exception:  # noqa: BLE001
        return ""


def get_mdns_name(ip: str) -> tuple[str, dict[str, str]]:
    """Try to get mDNS name and service info for the device."""
    hostname = ""
    service_info = {}
    
    try:
        import subprocess
        # Try avahi-resolve for hostname
        result = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True,
            text=True,
            timeout=1
        )
        if result.returncode == 0 and result.stdout:
            # Parse avahi output: "192.168.1.100 hostname.local"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                mdns_name = parts[1]
                if mdns_name.endswith(".local"):
                    mdns_name = mdns_name[:-6]
                hostname = mdns_name
                _LOGGER.debug("Found mDNS hostname for %s: %s", ip, hostname)
    except Exception:  # noqa: BLE001
        pass
    
    # Try to get service information
    try:
        import subprocess
        # Query for common services
        services = [
            "_googlecast._tcp",
            "_airplay._tcp", 
            "_hap._tcp",
            "_esphomelib._tcp",
            "_companion-link._tcp",
            "_androidtvremote2._tcp"
        ]
        
        for service in services:
            try:
                result = subprocess.run(
                    ["avahi-browse", "-ptr", service],
                    capture_output=True,
                    text=True,
                    timeout=1
                )
                if result.returncode == 0 and ip in result.stdout:
                    # Extract service details for this IP
                    lines = result.stdout.split("\n")
                    for i, line in enumerate(lines):
                        if f"address = [{ip}]" in line:
                            # Look for service name in previous lines
                            for j in range(max(0, i-5), i):
                                if "=" in lines[j] and service in lines[j]:
                                    service_name = lines[j].split(service)[0].strip().split()[-1]
                                    service_info[service] = service_name
                                    _LOGGER.debug("Found mDNS service for %s: %s = %s", ip, service, service_name)
                                    break
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    
    return hostname, service_info


def perform_arp_scan(subnets: list[str]) -> dict[str, tuple[str, str, str, dict]]:
    """Scan subnets using ARP and return mapping mac -> (ip, hostname, vendor)."""
    from netaddr import IPNetwork  # local import
    from scapy.all import arping, conf, getmacbyip  # type: ignore

    conf.verb = 0
    hits: dict[str, str] = {}
    _LOGGER.info("Starting ARP scan for subnets: %s", subnets)
    
    # First, try to detect known problematic devices directly
    known_devices = [
        "192.168.1.15",  # Sony TV
        "192.168.1.11",  # MacBook
        "192.168.1.38",  # iPad
    ]
    
    for ip in known_devices:
        try:
            # Try to get MAC directly
            mac = getmacbyip(ip)
            if mac and mac != "ff:ff:ff:ff:ff:ff":
                mac = mac.upper()
                hits[mac] = ip
                _LOGGER.info("Found known device via direct lookup: MAC=%s, IP=%s", mac, ip)
        except Exception as e:
            _LOGGER.debug("Could not get MAC for %s: %s", ip, e)
    
    for net in subnets:
        try:
            str(IPNetwork(net))
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Invalid subnet %s: %s", net, e)
            continue
        try:
            _LOGGER.debug("Scanning subnet: %s", net)
            # Try multiple times for better detection
            for attempt in range(2):
                if attempt > 0:
                    _LOGGER.debug("ARP scan attempt %d for subnet %s", attempt + 1, net)
                ans, unans = arping(net, timeout=3, verbose=0, retry=2)
                _LOGGER.debug("ARP scan of %s: %d answered, %d unanswered", net, len(ans), len(unans))
                for _, r in ans:
                    ip = r.psrc
                    # Use hwsrc for hardware (MAC) address
                    mac = r.hwsrc.upper() if hasattr(r, "hwsrc") else None
                    if ip and mac:
                        if mac not in hits:
                            hits[mac] = ip
                            _LOGGER.info("Found device via ARP: MAC=%s, IP=%s", mac, ip)
                        else:
                            _LOGGER.debug("Device already found: MAC=%s, IP=%s", mac, ip)
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Error scanning subnet %s: %s", net, e)
            import traceback
            _LOGGER.debug("Traceback: %s", traceback.format_exc())
            continue

    _LOGGER.info("ARP scan complete. Found %d unique devices", len(hits))
    
    # Log all discovered IPs
    for mac, ip in hits.items():
        _LOGGER.debug("Device in hits: %s -> %s", mac, ip)
    results: dict[str, tuple[str, str, str, dict]] = {}
    for mac, ip in hits.items():
        # Try multiple methods to get device name
        name = ""
        
        # Method 1: Standard reverse DNS
        try:
            dns_name = socket.gethostbyaddr(ip)[0]
            # Check if it's actually a hostname, not IP
            if dns_name != ip and not dns_name.replace(".", "").replace("-", "").isdigit():
                name = dns_name
                _LOGGER.debug("Got DNS name for %s: %s", ip, name)
        except Exception:  # noqa: BLE001
            pass
        
        # Method 2: Try mDNS
        mdns_name, mdns_services = get_mdns_name(ip)
        if mdns_name and not name:
            name = mdns_name
            _LOGGER.debug("Got mDNS name for %s: %s", ip, name)
        
        # Method 3: Get vendor from MAC
        vendor = get_vendor_from_mac(mac)
        if vendor:
            _LOGGER.debug("Got vendor for %s: %s", mac, vendor)
        
        results[mac] = (ip, name, vendor, mdns_services)
        _LOGGER.debug("Device %s: IP=%s, hostname=%s, vendor=%s, services=%s", 
                     mac, ip, name or "(none)", vendor or "(none)", mdns_services)
    return results


class LanwatchCoordinator(DataUpdateCoordinator[dict[str, DeviceInfo]]):
    def __init__(
        self,
        hass: HomeAssistant,
        subnets: list[str],
        interval_s: int,
        absent_after_s: int,
        entry_id: str,
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
            _LOGGER.info("Loading %d stored devices", len(stored_data))
            for mac, device_data in stored_data.items():
                # Ensure MAC is uppercase
                mac = mac.upper()
                device_data["last_seen"] = datetime.fromisoformat(device_data["last_seen"])
                device_data["mac"] = mac  # Ensure MAC in data is also uppercase
                
                # Handle migration from old format - remove unknown fields
                valid_fields = {"ip", "name", "mac", "last_seen", "vendor", "mdns_services"}
                cleaned_data = {k: v for k, v in device_data.items() if k in valid_fields}
                
                # Handle old fields that might exist
                if "mdns_name" in device_data:
                    # Migrate old mdns_name to name if name is empty
                    if not cleaned_data.get("name") and device_data["mdns_name"]:
                        cleaned_data["name"] = device_data["mdns_name"]
                
                if "netbios_name" in device_data:
                    # Ignore old netbios_name field
                    pass
                
                # Ensure mdns_services is a dict
                if "mdns_services" not in cleaned_data:
                    cleaned_data["mdns_services"] = {}
                elif cleaned_data["mdns_services"] is None:
                    cleaned_data["mdns_services"] = {}
                
                try:
                    self._seen[mac] = DeviceInfo(**cleaned_data)
                except Exception as e:
                    _LOGGER.error("Failed to load device %s: %s", mac, e)
                    # Create a minimal device entry
                    self._seen[mac] = DeviceInfo(
                        ip=cleaned_data.get("ip", ""),
                        name=cleaned_data.get("name", ""),
                        mac=mac,
                        last_seen=cleaned_data.get("last_seen", dt_util.utcnow()),
                        vendor=cleaned_data.get("vendor", ""),
                        mdns_services={}
                    )
        else:
            _LOGGER.info("No stored devices found, starting fresh")
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
        _LOGGER.debug("Starting LanWatch scan")
        pairs = perform_arp_scan(self._subnets)
        now = dt_util.utcnow()
        
        for mac, (ip, name, vendor, mdns_services) in pairs.items():
            # Ensure MAC is uppercase for consistency
            mac = mac.upper()
            if mac not in self._seen:
                self._new_devices.add(mac)
                _LOGGER.info("New device discovered: MAC=%s, IP=%s, Name=%s, Vendor=%s, Services=%s", 
                            mac, ip, name or "(none)", vendor or "(none)", mdns_services)
            else:
                _LOGGER.debug("Updating existing device: MAC=%s, IP=%s, Name=%s", mac, ip, name or "(none)")
            
            # Preserve existing vendor if new scan didn't find one
            if mac in self._seen and not vendor:
                vendor = self._seen[mac].vendor
            
            self._seen[mac] = DeviceInfo(
                ip=ip, 
                name=name or "", 
                mac=mac, 
                last_seen=now,
                vendor=vendor or "",
                mdns_services=mdns_services or {}
            )

        _LOGGER.info("Scan complete. Total devices tracked: %d, New devices: %d", 
                    len(self._seen), len(self._new_devices))
        
        # Log devices that might be missing
        expected_ips = ["192.168.1.15", "192.168.1.11", "192.168.1.38", "192.168.1.41"]
        for expected_ip in expected_ips:
            found = False
            for device in self._seen.values():
                if device.ip == expected_ip:
                    found = True
                    _LOGGER.debug("Expected device found: %s -> %s (%s)", expected_ip, device.mac, device.name)
                    break
            if not found:
                _LOGGER.warning("Expected device NOT found at IP: %s", expected_ip)
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