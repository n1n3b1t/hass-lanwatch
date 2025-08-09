"""Basic unit tests for LanWatch that don't require Home Assistant."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch


def test_config_constants():
    """Test configuration constants by reading the const.py file directly."""
    # Since importing triggers __init__.py which needs HA, we'll check the constants directly
    import os

    const_file = os.path.join(
        os.path.dirname(__file__), "..", "custom_components", "lanwatch", "const.py"
    )

    with open(const_file) as f:
        content = f.read()

    # Simple parsing to verify constants
    assert 'DOMAIN = "lanwatch"' in content
    assert 'CONF_SUBNETS = "subnets"' in content
    assert 'CONF_INTERVAL = "interval"' in content
    assert 'CONF_ABSENT_AFTER = "absent_after"' in content


def test_perform_arp_scan_with_mock():
    """Test ARP scanning with mocked scapy and no HA dependencies."""
    # Mock all the dependencies including scapy
    with patch.dict(
        "sys.modules",
        {
            "homeassistant": MagicMock(),
            "homeassistant.config_entries": MagicMock(),
            "homeassistant.const": MagicMock(),
            "homeassistant.core": MagicMock(),
            "homeassistant.helpers": MagicMock(),
            "homeassistant.helpers.storage": MagicMock(),
            "homeassistant.helpers.update_coordinator": MagicMock(),
            "homeassistant.util": MagicMock(),
            "homeassistant.util.dt": MagicMock(),
            "scapy": MagicMock(),
            "scapy.all": MagicMock(),
            "netaddr": MagicMock(),
        },
    ):
        # Mock netaddr.IPNetwork
        mock_ipnetwork = MagicMock()
        mock_ipnetwork.return_value = "192.168.1.0/24"
        sys.modules["netaddr"].IPNetwork = mock_ipnetwork

        # Mock getmacbyip
        mock_getmacbyip = MagicMock()
        mock_getmacbyip.return_value = None
        sys.modules["scapy.all"].getmacbyip = mock_getmacbyip

        # Mock arping
        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.50"
        mock_response.hwsrc = "AA:BB:CC:DD:EE:FF"

        mock_arping = MagicMock()
        mock_arping.return_value = ([(None, mock_response)], [])
        sys.modules["scapy.all"].arping = mock_arping

        # Mock conf
        mock_conf = MagicMock()
        mock_conf.verb = 0
        sys.modules["scapy.all"].conf = mock_conf

        # Now we can import the module
        from custom_components.lanwatch import perform_arp_scan

        with patch("socket.gethostbyaddr") as mock_dns:
            mock_dns.return_value = ("test-host.local", [], [])

            with patch("custom_components.lanwatch.monitor_dhcp_packets", return_value={}):
                results = perform_arp_scan(["192.168.1.0/24"])

                assert "AA:BB:CC:DD:EE:FF" in results
                # Check the tuple elements (ip, name, vendor, mdns_services, device_type,
                # os_hint, open_ports, dhcp_info, capabilities)
                result_tuple = results["AA:BB:CC:DD:EE:FF"]
                assert result_tuple[0] == "192.168.1.50"  # IP
                assert result_tuple[1] == "test-host.local"  # hostname


def test_perform_arp_scan_invalid_subnet():
    """Test ARP scan with invalid subnet."""
    with patch.dict(
        "sys.modules",
        {
            "homeassistant": MagicMock(),
            "homeassistant.config_entries": MagicMock(),
            "homeassistant.const": MagicMock(),
            "homeassistant.core": MagicMock(),
            "homeassistant.helpers": MagicMock(),
            "homeassistant.helpers.storage": MagicMock(),
            "homeassistant.helpers.update_coordinator": MagicMock(),
            "homeassistant.util": MagicMock(),
            "homeassistant.util.dt": MagicMock(),
            "scapy": MagicMock(),
            "scapy.all": MagicMock(),
            "netaddr": MagicMock(),
        },
    ):
        # Mock IPNetwork to raise exception for invalid subnet
        mock_ipnetwork = MagicMock()
        mock_ipnetwork.side_effect = Exception("Invalid subnet")
        sys.modules["netaddr"].IPNetwork = mock_ipnetwork

        # Mock getmacbyip
        mock_getmacbyip = MagicMock()
        mock_getmacbyip.return_value = None
        sys.modules["scapy.all"].getmacbyip = mock_getmacbyip

        # Mock conf
        mock_conf = MagicMock()
        mock_conf.verb = 0
        sys.modules["scapy.all"].conf = mock_conf

        from custom_components.lanwatch import perform_arp_scan

        mock_arping = MagicMock()
        sys.modules["scapy.all"].arping = mock_arping

        results = perform_arp_scan(["invalid_subnet"])

        # Should return empty dict for invalid subnet
        assert results == {}
        mock_arping.assert_not_called()


def test_perform_arp_scan_with_dns_failure():
    """Test ARP scanning when DNS lookup fails."""
    with patch.dict(
        "sys.modules",
        {
            "homeassistant": MagicMock(),
            "homeassistant.config_entries": MagicMock(),
            "homeassistant.const": MagicMock(),
            "homeassistant.core": MagicMock(),
            "homeassistant.helpers": MagicMock(),
            "homeassistant.helpers.storage": MagicMock(),
            "homeassistant.helpers.update_coordinator": MagicMock(),
            "homeassistant.util": MagicMock(),
            "homeassistant.util.dt": MagicMock(),
            "scapy": MagicMock(),
            "scapy.all": MagicMock(),
            "netaddr": MagicMock(),
        },
    ):
        # Mock netaddr.IPNetwork
        mock_ipnetwork = MagicMock()
        mock_ipnetwork.return_value = "192.168.1.0/24"
        sys.modules["netaddr"].IPNetwork = mock_ipnetwork

        # Mock getmacbyip
        mock_getmacbyip = MagicMock()
        mock_getmacbyip.return_value = None
        sys.modules["scapy.all"].getmacbyip = mock_getmacbyip

        # Mock conf
        mock_conf = MagicMock()
        mock_conf.verb = 0
        sys.modules["scapy.all"].conf = mock_conf

        class Pkt:
            def __init__(self, ip, mac) -> None:
                self.psrc = ip
                self.hwsrc = mac

        def fake_arping(_net, timeout=3, verbose=0, retry=2):  # noqa: ARG001
            return ([(None, Pkt("192.168.1.50", "AA:BB:CC:DD:EE:FF"))], [])

        mock_arping = MagicMock(side_effect=fake_arping)
        sys.modules["scapy.all"].arping = mock_arping

        from custom_components.lanwatch import perform_arp_scan

        with (
            patch("socket.gethostbyaddr", side_effect=Exception("DNS lookup failed")),
            patch("custom_components.lanwatch.monitor_dhcp_packets", return_value={}),
        ):
            pairs = perform_arp_scan(["192.168.1.0/24"])
            # Should still return the device with empty hostname
            assert "AA:BB:CC:DD:EE:FF" in pairs
            result_tuple = pairs["AA:BB:CC:DD:EE:FF"]
            assert result_tuple[0] == "192.168.1.50"
            assert result_tuple[1] == ""  # Empty hostname


def test_device_info_dataclass():
    """Test DeviceInfo dataclass."""
    from datetime import datetime

    # Mock HomeAssistant modules
    with patch.dict(
        "sys.modules",
        {
            "homeassistant": MagicMock(),
            "homeassistant.config_entries": MagicMock(),
            "homeassistant.const": MagicMock(),
            "homeassistant.core": MagicMock(),
            "homeassistant.helpers": MagicMock(),
            "homeassistant.helpers.storage": MagicMock(),
            "homeassistant.helpers.update_coordinator": MagicMock(),
            "homeassistant.util": MagicMock(),
            "homeassistant.util.dt": MagicMock(),
        },
    ):
        from custom_components.lanwatch import DeviceInfo

        device = DeviceInfo(
            ip="192.168.1.100",
            name="test-device",
            mac="AA:BB:CC:DD:EE:FF",
            last_seen=datetime.now(),
            vendor="Test Vendor",
            device_type="computer",
            os_hint="Linux",
            open_ports=[22, 80],
            dhcp_info={"hostname": "test-device"},
            capabilities=["ssh", "web"],
        )

        assert device.ip == "192.168.1.100"
        assert device.name == "test-device"
        assert device.mac == "AA:BB:CC:DD:EE:FF"
        assert device.vendor == "Test Vendor"
        assert device.device_type == "computer"
        assert device.os_hint == "Linux"
        assert device.open_ports == [22, 80]
        assert device.dhcp_info == {"hostname": "test-device"}
        assert device.capabilities == ["ssh", "web"]
