"""Basic unit tests for LanWatch custom component."""

from unittest.mock import MagicMock, patch

from custom_components.lanwatch import DeviceInfo, perform_arp_scan
from custom_components.lanwatch.const import DOMAIN


def test_device_info_dataclass():
    """Test DeviceInfo dataclass."""
    from datetime import datetime
    
    device = DeviceInfo(
        ip="192.168.1.100",
        name="test-device",
        mac="AA:BB:CC:DD:EE:FF",
        last_seen=datetime.now(),
        vendor="Test Vendor"
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


def test_domain_constant():
    """Test domain constant is set correctly."""
    assert DOMAIN == "lanwatch"