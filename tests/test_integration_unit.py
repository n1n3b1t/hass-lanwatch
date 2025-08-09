from __future__ import annotations

from unittest.mock import patch

from custom_components.lanwatch.__init__ import perform_arp_scan


def test_perform_arp_scan_monkeypatched_dns_and_arp():
    class Pkt:
        def __init__(self, ip, mac) -> None:
            self.psrc = ip
            self.src_mac = mac

    def fake_arping(_net, timeout=3, verbose=0):  # noqa: ARG001
        return ([(None, Pkt("192.168.1.50", "AA:BB:CC:DD:EE:FF"))], None)

    with patch("scapy.all.arping", side_effect=fake_arping), patch(
        "socket.gethostbyaddr",
        return_value=("host1.local", [], ["192.168.1.50"]),
    ):
        pairs = perform_arp_scan(["192.168.1.0/24"])
        assert pairs == {"AA:BB:CC:DD:EE:FF": ("192.168.1.50", "host1.local")} 