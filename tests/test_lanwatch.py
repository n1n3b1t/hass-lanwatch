"""Tests for LanWatch custom component."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from custom_components.lanwatch import DeviceInfo, perform_arp_scan
from custom_components.lanwatch.const import (
    CONF_ABSENT_AFTER,
    CONF_INTERVAL,
    CONF_SUBNETS,
    DOMAIN,
)


def test_device_info_dataclass():
    """Test DeviceInfo dataclass."""
    from datetime import datetime

    device = DeviceInfo(
        ip="192.168.1.100",
        name="test-device",
        mac="AA:BB:CC:DD:EE:FF",
        last_seen=datetime.now(),
        vendor="Test Vendor",
    )

    assert device.ip == "192.168.1.100"
    assert device.name == "test-device"
    assert device.mac == "AA:BB:CC:DD:EE:FF"
    assert device.vendor == "Test Vendor"


def test_perform_arp_scan_with_mock():
    """Test ARP scanning with mocked scapy."""
    with patch("scapy.all.arping") as mock_arping:
        # Mock ARP response
        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.50"
        mock_response.src_mac = "AA:BB:CC:DD:EE:FF"

        mock_arping.return_value = ([(None, mock_response)], None)

        with patch("socket.gethostbyaddr") as mock_dns:
            mock_dns.return_value = ("test-host.local", [], [])

            results = perform_arp_scan(["192.168.1.0/24"])

            assert "AA:BB:CC:DD:EE:FF" in results
            assert results["AA:BB:CC:DD:EE:FF"] == ("192.168.1.50", "test-host.local")


def test_perform_arp_scan_invalid_subnet():
    """Test ARP scan with invalid subnet."""
    with patch("scapy.all.arping") as mock_arping:
        results = perform_arp_scan(["invalid_subnet"])

        # Should return empty dict for invalid subnet
        assert results == {}
        mock_arping.assert_not_called()


def test_perform_arp_scan_with_dns_failure():
    """Test ARP scanning when DNS lookup fails."""

    class Pkt:
        def __init__(self, ip, mac) -> None:
            self.psrc = ip
            self.src_mac = mac

    def fake_arping(_net, timeout=3, verbose=0):  # noqa: ARG001
        return ([(None, Pkt("192.168.1.50", "AA:BB:CC:DD:EE:FF"))], None)

    with patch("scapy.all.arping", side_effect=fake_arping), patch(
        "socket.gethostbyaddr",
        side_effect=Exception("DNS lookup failed"),
    ):
        pairs = perform_arp_scan(["192.168.1.0/24"])
        # Should still return the device with empty hostname
        assert pairs == {"AA:BB:CC:DD:EE:FF": ("192.168.1.50", "")}


def test_domain_constant():
    """Test domain constant is set correctly."""
    assert DOMAIN == "lanwatch"


def test_config_constants():
    """Test configuration constants."""
    assert CONF_SUBNETS == "subnets"
    assert CONF_INTERVAL == "interval"
    assert CONF_ABSENT_AFTER == "absent_after"


# Home Assistant integration tests
try:
    from homeassistant.core import HomeAssistant  # type: ignore
except ImportError:
    HomeAssistant = None  # type: ignore[misc,assignment]

pytestmark = pytest.mark.asyncio


@pytest.mark.skipif(
    HomeAssistant is None, reason="homeassistant test fixture not available"
)
async def test_setup_and_entity_creation(hass: HomeAssistant) -> None:
    """Test component setup and entity creation."""
    # Fake scan results
    with patch(
        "custom_components.lanwatch.__init__.perform_arp_scan",
        return_value={"AA:BB:CC:DD:EE:FF": ("192.168.1.50", "host1.local")},
    ):
        entry = hass.config_entries.async_create_entry(
            domain=DOMAIN,
            title="LanWatch",
            data={
                CONF_SUBNETS: ["192.168.1.0/24"],
                CONF_INTERVAL: 60,
                CONF_ABSENT_AFTER: 300,
            },
        )
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        # Device tracker should register
        ent_reg = hass.helpers.entity_registry.async_get(hass)
        found = [e for e in ent_reg.entities if e.startswith("device_tracker.lanwatch_")]
        assert found