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
    device_type: str = ""  # router, phone, tv, iot, computer, printer, etc.
    os_hint: str = ""  # iOS, Android, Windows, Linux, macOS, etc.
    open_ports: list = field(default_factory=list)  # List of open TCP/UDP ports
    dhcp_info: dict = field(default_factory=dict)  # DHCP hostname, vendor_id, client_id
    capabilities: list = field(default_factory=list)  # web, ssh, smb, airplay, etc.


def monitor_dhcp_packets(timeout: int = 10) -> dict[str, dict]:
    """Monitor DHCP packets to gather device information."""
    from scapy.all import BOOTP, DHCP, sniff  # type: ignore

    dhcp_data = {}

    def process_dhcp_packet(packet):  # type: ignore
        """Process DHCP packets to extract device information."""
        if DHCP in packet:
            # Get MAC address from BOOTP layer
            if BOOTP in packet:
                mac = packet[BOOTP].chaddr[:6].hex()
                # Format MAC address properly
                mac = ":".join([mac[i : i + 2] for i in range(0, len(mac), 2)]).upper()

                dhcp_options = {}
                for option in packet[DHCP].options:
                    if isinstance(option, tuple):
                        opt_name, opt_value = option
                        if opt_name == "hostname":
                            val = opt_value.decode() if isinstance(opt_value, bytes) else opt_value
                            dhcp_options["hostname"] = val
                        elif opt_name == "vendor_class_id":
                            val = opt_value.decode() if isinstance(opt_value, bytes) else opt_value
                            dhcp_options["vendor_class_id"] = val
                        elif opt_name == "client_id":
                            val = opt_value.hex() if isinstance(opt_value, bytes) else opt_value
                            dhcp_options["client_id"] = val
                        elif opt_name == "requested_addr":
                            dhcp_options["requested_addr"] = opt_value

                if mac and dhcp_options:
                    dhcp_data[mac] = dhcp_options
                    _LOGGER.debug("DHCP packet from %s: %s", mac, dhcp_options)

    try:
        # Sniff DHCP packets on UDP port 67 and 68
        _LOGGER.debug("Starting DHCP packet monitoring for %d seconds", timeout)
        sniff(
            filter="udp and (port 67 or port 68)", prn=process_dhcp_packet, timeout=timeout, store=0
        )
        _LOGGER.debug("DHCP monitoring complete. Captured data for %d devices", len(dhcp_data))
    except Exception as e:
        _LOGGER.debug("DHCP monitoring failed (may need elevated privileges): %s", e)

    return dhcp_data


def scan_common_ports(ip: str) -> tuple[list[int], list[str]]:
    """Scan common TCP/UDP ports to identify device capabilities."""
    from scapy.all import IP, TCP, UDP, conf, sr1  # type: ignore

    conf.verb = 0
    open_ports = []
    capabilities = []

    # Common ports to check (port, protocol, capability)
    ports_to_check = [
        (22, "tcp", "ssh"),  # SSH
        (80, "tcp", "web"),  # HTTP
        (443, "tcp", "web"),  # HTTPS
        (445, "tcp", "smb"),  # SMB/Windows shares
        (548, "tcp", "afp"),  # AFP/Apple shares
        (631, "tcp", "printer"),  # IPP/CUPS printing
        (3389, "tcp", "rdp"),  # Remote Desktop
        (5000, "tcp", "airplay"),  # AirPlay (macOS) / Synology DSM
        (5353, "udp", "mdns"),  # mDNS/Bonjour
        (8080, "tcp", "web"),  # Alternative HTTP
        (8883, "tcp", "mqtt"),  # MQTT/IoT
        (9100, "tcp", "printer"),  # JetDirect printing
    ]

    for port, protocol, capability in ports_to_check:
        try:
            if protocol == "tcp":
                # Send SYN packet
                packet = IP(dst=ip) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=0.5, verbose=0)

                if response and response.haslayer(TCP):
                    if response[TCP].flags == 18:  # SYN-ACK
                        open_ports.append(port)
                        if capability not in capabilities:
                            capabilities.append(capability)
                        _LOGGER.debug(
                            "Port %d/tcp open on %s (capability: %s)", port, ip, capability
                        )

            elif protocol == "udp":
                # UDP scanning is less reliable, only check critical ones
                if port == 5353:  # mDNS
                    packet = IP(dst=ip) / UDP(dport=port)
                    response = sr1(packet, timeout=0.5, verbose=0)
                    if response:
                        if capability not in capabilities:
                            capabilities.append(capability)

        except Exception:  # noqa: BLE001
            pass

    return open_ports, capabilities


def detect_device_type_and_os(
    mac: str,
    vendor: str,
    dhcp_info: dict,
    mdns_services: dict,
    open_ports: list,
    capabilities: list,
) -> tuple[str, str]:
    """Detect device type and OS based on collected information."""
    device_type = ""
    os_hint = ""

    # Special handling: If vendor is Apple and port 5000 is open, it's likely a Mac
    # (AirPlay Receiver), not a Synology NAS
    if vendor and "apple" in vendor.lower() and 5000 in open_ports:
        device_type = "computer"
        os_hint = "macOS"
        return device_type, os_hint

    # Check mDNS services first (most reliable)
    if mdns_services:
        # Apple devices
        if "_companion-link._tcp" in mdns_services or "_airplay._tcp" in mdns_services:
            os_hint = "iOS/macOS"
            if "_touch-able._tcp" in mdns_services:
                device_type = "tv"  # Apple TV
            elif "iPad" in str(mdns_services.values()):
                device_type = "tablet"
                os_hint = "iPadOS"
            elif "iPhone" in str(mdns_services.values()):
                device_type = "phone"
                os_hint = "iOS"
            elif "MacBook" in str(mdns_services.values()) or "Mac" in str(mdns_services.values()):
                device_type = "computer"
                os_hint = "macOS"
            else:
                device_type = "phone"  # Default for Apple

        # Google/Android devices
        elif "_googlecast._tcp" in mdns_services or "_androidtvremote2._tcp" in mdns_services:
            if "_androidtvremote2._tcp" in mdns_services:
                device_type = "tv"
                os_hint = "Android TV"
            else:
                device_type = "media_player"
                os_hint = "Google Cast"

        # Smart home devices
        elif "_esphomelib._tcp" in mdns_services:
            device_type = "iot"
            os_hint = "ESPHome"
        elif "_hap._tcp" in mdns_services or "_homekit._tcp" in mdns_services:
            device_type = "iot"
            os_hint = "HomeKit"

        # Printers
        elif "_printer._tcp" in mdns_services or "_ipp._tcp" in mdns_services:
            device_type = "printer"

        # Media devices
        elif "_sonos._tcp" in mdns_services:
            device_type = "speaker"
            os_hint = "Sonos"
        elif "_spotify-connect._tcp" in mdns_services:
            device_type = "speaker"

    # Check DHCP info for additional hints
    if dhcp_info and not device_type:
        vendor_class = dhcp_info.get("vendor_class_id", "").lower()
        hostname = dhcp_info.get("hostname", "").lower()

        # OS detection from DHCP vendor class
        if "android" in vendor_class:
            os_hint = "Android"
            device_type = "phone"
        elif "iphone" in vendor_class or "ios" in vendor_class:
            os_hint = "iOS"
            device_type = "phone"
        elif "ipad" in vendor_class:
            os_hint = "iPadOS"
            device_type = "tablet"
        elif "windows" in vendor_class or "msft" in vendor_class:
            os_hint = "Windows"
            device_type = "computer"
        elif "linux" in vendor_class:
            os_hint = "Linux"
            device_type = "computer"
        elif "xbox" in vendor_class:
            os_hint = "Xbox"
            device_type = "game_console"
        elif "playstation" in vendor_class or "ps4" in vendor_class or "ps5" in vendor_class:
            os_hint = "PlayStation"
            device_type = "game_console"

        # Device type from hostname
        if not device_type:
            if "printer" in hostname:
                device_type = "printer"
            elif "tv" in hostname or "bravia" in hostname:
                device_type = "tv"
            elif "echo" in hostname or "alexa" in hostname:
                device_type = "speaker"
                os_hint = "Alexa"
            elif "chromecast" in hostname:
                device_type = "media_player"
                os_hint = "Google Cast"

    # Check vendor name
    if vendor and not device_type:
        vendor_lower = vendor.lower()
        if "apple" in vendor_lower:
            os_hint = "iOS/macOS"
            # MAC prefix hints for Apple devices (older Apple TV)
            apple_tv_prefixes = (
                "00:17:F2",
                "00:1B:63",
                "00:1E:C2",
                "00:1F:F3",
                "00:21:E9",
                "00:22:41",
                "00:23:12",
                "00:23:32",
                "00:23:6C",
                "00:23:DF",
                "00:24:36",
                "00:25:00",
                "00:25:4B",
                "00:25:BC",
                "00:26:08",
                "00:26:4A",
                "00:26:B0",
                "00:26:BB",
            )
            if mac.startswith(apple_tv_prefixes):
                device_type = "tv"  # Older Apple TV
            elif mac.startswith(("F0:18:98", "F0:99:BF")):
                device_type = "watch"
            elif "afp" in capabilities or "airplay" in capabilities:
                # If we see AFP or AirPlay, it's likely a Mac
                device_type = "computer"
                os_hint = "macOS"
            elif open_ports and (22 in open_ports or 5000 in open_ports):
                # SSH or port 5000 on Apple device likely means Mac
                device_type = "computer"
                os_hint = "macOS"
            else:
                device_type = "phone"  # Default for Apple

        elif "samsung" in vendor_lower:
            if mac.startswith(("00:16:32", "00:1D:F6")):
                device_type = "tv"
                os_hint = "Tizen"
            else:
                device_type = "phone"
                os_hint = "Android"

        elif "google" in vendor_lower:
            device_type = "media_player"
            os_hint = "Google Cast"

        elif "amazon" in vendor_lower:
            device_type = "speaker"
            os_hint = "Alexa"

        elif "espressif" in vendor_lower:
            device_type = "iot"
            os_hint = "ESP32/ESP8266"

        elif "raspberry" in vendor_lower:
            device_type = "computer"
            os_hint = "Raspberry Pi OS"

        elif any(
            tv in vendor_lower for tv in ["lg", "sony", "vizio", "tcl", "philips", "panasonic"]
        ):
            device_type = "tv"

        elif "synology" in vendor_lower:
            device_type = "nas"
            os_hint = "DSM"

        elif "asustek" in vendor_lower or "asus" in vendor_lower:
            # ASUS makes routers and computers
            device_type = "network"  # Most commonly routers

        elif "ubiquiti" in vendor_lower or "unifi" in vendor_lower:
            device_type = "network"
            os_hint = "UniFi"

    # Check open ports/capabilities
    if not device_type and capabilities:
        if "printer" in capabilities:
            device_type = "printer"
        elif "rdp" in capabilities:
            device_type = "computer"
            os_hint = "Windows"
        elif "afp" in capabilities or ("airplay" in capabilities and "ssh" in capabilities):
            # AFP or AirPlay+SSH strongly indicates macOS
            device_type = "computer"
            os_hint = "macOS"
        elif "smb" in capabilities and "afp" in capabilities:
            device_type = "computer"
            os_hint = "macOS"
        elif "smb" in capabilities:
            device_type = "computer"
            os_hint = "Windows"
        elif "ssh" in capabilities and "web" in capabilities:
            device_type = "computer"
            os_hint = "Linux"
        elif "mqtt" in capabilities:
            device_type = "iot"

    # Default fallback
    if not device_type:
        if open_ports:
            if 22 in open_ports or 3389 in open_ports:
                device_type = "computer"
            else:
                device_type = "device"
        else:
            device_type = "device"

    return device_type, os_hint


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
            ["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=1
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

        # Query for common services - expanded list
        services = [
            "_googlecast._tcp",  # Chromecast/Google devices
            "_airplay._tcp",  # Apple AirPlay
            "_raop._tcp",  # Remote Audio Output Protocol (AirPlay)
            "_hap._tcp",  # HomeKit Accessory Protocol
            "_homekit._tcp",  # HomeKit devices
            "_esphomelib._tcp",  # ESPHome devices
            "_companion-link._tcp",  # Apple devices
            "_androidtvremote2._tcp",  # Android TV
            "_spotify-connect._tcp",  # Spotify Connect speakers
            "_sonos._tcp",  # Sonos speakers
            "_printer._tcp",  # Network printers
            "_ipp._tcp",  # Internet Printing Protocol
            "_http._tcp",  # Web services
            "_ssh._tcp",  # SSH services
            "_smb._tcp",  # SMB/Windows shares
            "_afpovertcp._tcp",  # Apple File Protocol
            "_device-info._tcp",  # Device information
            "_workstation._tcp",  # Workstation/computer
            "_presence._tcp",  # Presence detection
            "_touch-able._tcp",  # Apple Remote devices
            "_daap._tcp",  # iTunes/Music sharing
            "_airport._tcp",  # Apple AirPort
            "_rfb._tcp",  # VNC Remote Framebuffer
            "_nvstream_dbd._tcp",  # NVIDIA GameStream
        ]

        for service in services:
            try:
                result = subprocess.run(
                    ["avahi-browse", "-ptr", service], capture_output=True, text=True, timeout=1
                )
                if result.returncode == 0 and ip in result.stdout:
                    # Extract service details for this IP
                    lines = result.stdout.split("\n")
                    for i, line in enumerate(lines):
                        if f"address = [{ip}]" in line:
                            # Look for service name in previous lines
                            for j in range(max(0, i - 5), i):
                                if "=" in lines[j] and service in lines[j]:
                                    service_name = lines[j].split(service)[0].strip().split()[-1]
                                    service_info[service] = service_name
                                    _LOGGER.debug(
                                        "Found mDNS service for %s: %s = %s",
                                        ip,
                                        service,
                                        service_name,
                                    )
                                    break
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass

    return hostname, service_info


def perform_arp_scan(
    subnets: list[str],
) -> dict[str, tuple[str, str, str, dict, str, str, list, dict, list]]:
    """Scan subnets using ARP and return comprehensive device information."""
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
                _LOGGER.debug(
                    "ARP scan of %s: %d answered, %d unanswered", net, len(ans), len(unans)
                )
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

    # Start passive DHCP monitoring in background (non-blocking)
    dhcp_data = {}
    try:
        # Quick DHCP scan (2 seconds)
        dhcp_data = monitor_dhcp_packets(timeout=2)
        _LOGGER.info("DHCP monitoring found data for %d devices", len(dhcp_data))
    except Exception as e:
        _LOGGER.debug("DHCP monitoring skipped: %s", e)

    # Log all discovered IPs
    for mac, ip in hits.items():
        _LOGGER.debug("Device in hits: %s -> %s", mac, ip)

    results: dict[str, tuple[str, str, str, dict, str, str, list, dict, list]] = {}
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

        # Method 4: Port scanning for capabilities (only for first scan or important devices)
        open_ports = []
        capabilities = []
        try:
            # Only scan ports for a subset of devices to avoid slowdown
            if len(results) < 10:  # Limit to first 10 devices
                open_ports, capabilities = scan_common_ports(ip)
                if open_ports:
                    _LOGGER.debug("Open ports for %s: %s", ip, open_ports)
        except Exception as e:
            _LOGGER.debug("Port scan failed for %s: %s", ip, e)

        # Method 5: Get DHCP info if available
        dhcp_info = dhcp_data.get(mac, {})
        if dhcp_info:
            _LOGGER.debug("DHCP info for %s: %s", mac, dhcp_info)
            # Use DHCP hostname if we don't have a name yet
            if not name and "hostname" in dhcp_info:
                name = dhcp_info["hostname"]

        # Method 6: Device type and OS detection
        device_type, os_hint = detect_device_type_and_os(
            mac, vendor, dhcp_info, mdns_services, open_ports, capabilities
        )
        if device_type or os_hint:
            _LOGGER.debug("Device %s detected as: type=%s, os=%s", mac, device_type, os_hint)

        results[mac] = (
            ip,
            name,
            vendor,
            mdns_services,
            device_type,
            os_hint,
            open_ports,
            dhcp_info,
            capabilities,
        )
        _LOGGER.debug(
            "Device %s: IP=%s, hostname=%s, vendor=%s, type=%s, os=%s",
            mac,
            ip,
            name or "(none)",
            vendor or "(none)",
            device_type or "(none)",
            os_hint or "(none)",
        )
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
                valid_fields = {
                    "ip",
                    "name",
                    "mac",
                    "last_seen",
                    "vendor",
                    "mdns_services",
                    "device_type",
                    "os_hint",
                    "open_ports",
                    "dhcp_info",
                    "capabilities",
                }
                cleaned_data = {k: v for k, v in device_data.items() if k in valid_fields}

                # Handle old fields that might exist
                if "mdns_name" in device_data:
                    # Migrate old mdns_name to name if name is empty
                    if not cleaned_data.get("name") and device_data["mdns_name"]:
                        cleaned_data["name"] = device_data["mdns_name"]

                if "netbios_name" in device_data:
                    # Ignore old netbios_name field
                    pass

                # Ensure dict/list fields have defaults
                if "mdns_services" not in cleaned_data:
                    cleaned_data["mdns_services"] = {}
                elif cleaned_data["mdns_services"] is None:
                    cleaned_data["mdns_services"] = {}

                # Ensure new fields have defaults for migration
                if "device_type" not in cleaned_data:
                    cleaned_data["device_type"] = ""
                if "os_hint" not in cleaned_data:
                    cleaned_data["os_hint"] = ""
                if "open_ports" not in cleaned_data:
                    cleaned_data["open_ports"] = []
                if "dhcp_info" not in cleaned_data:
                    cleaned_data["dhcp_info"] = {}
                if "capabilities" not in cleaned_data:
                    cleaned_data["capabilities"] = []

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
                        mdns_services={},
                        device_type="",
                        os_hint="",
                        open_ports=[],
                        dhcp_info={},
                        capabilities=[],
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

        for mac, (
            ip,
            name,
            vendor,
            mdns_services,
            device_type,
            os_hint,
            open_ports,
            dhcp_info,
            capabilities,
        ) in pairs.items():
            # Ensure MAC is uppercase for consistency
            mac = mac.upper()
            if mac not in self._seen:
                self._new_devices.add(mac)
                _LOGGER.info(
                    "New device discovered: MAC=%s, IP=%s, Name=%s, Vendor=%s, Type=%s, OS=%s",
                    mac,
                    ip,
                    name or "(none)",
                    vendor or "(none)",
                    device_type or "(none)",
                    os_hint or "(none)",
                )
            else:
                _LOGGER.debug(
                    "Updating existing device: MAC=%s, IP=%s, Name=%s, Type=%s",
                    mac,
                    ip,
                    name or "(none)",
                    device_type or "(none)",
                )

            # Preserve existing data if new scan didn't find it
            if mac in self._seen:
                existing = self._seen[mac]
                if not vendor:
                    vendor = existing.vendor
                if not device_type:
                    device_type = existing.device_type
                if not os_hint:
                    os_hint = existing.os_hint
                if not open_ports and existing.open_ports:
                    open_ports = existing.open_ports
                if not dhcp_info and existing.dhcp_info:
                    dhcp_info = existing.dhcp_info
                if not capabilities and existing.capabilities:
                    capabilities = existing.capabilities

            self._seen[mac] = DeviceInfo(
                ip=ip,
                name=name or "",
                mac=mac,
                last_seen=now,
                vendor=vendor or "",
                mdns_services=mdns_services or {},
                device_type=device_type or "",
                os_hint=os_hint or "",
                open_ports=open_ports or [],
                dhcp_info=dhcp_info or {},
                capabilities=capabilities or [],
            )

        _LOGGER.info(
            "Scan complete. Total devices tracked: %d, New devices: %d",
            len(self._seen),
            len(self._new_devices),
        )

        # Log devices that might be missing
        expected_ips = ["192.168.1.15", "192.168.1.11", "192.168.1.38", "192.168.1.41"]
        for expected_ip in expected_ips:
            found = False
            for device in self._seen.values():
                if device.ip == expected_ip:
                    found = True
                    _LOGGER.debug(
                        "Expected device found: %s -> %s (%s)", expected_ip, device.mac, device.name
                    )
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
