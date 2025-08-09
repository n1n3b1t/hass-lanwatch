from __future__ import annotations

from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.lanwatch.const import CONF_ABSENT_AFTER, CONF_INTERVAL, CONF_SUBNETS, DOMAIN

pytestmark = pytest.mark.asyncio


async def test_setup_and_entity_creation(hass: HomeAssistant) -> None:
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
        found = [e for e in ent_reg.entities if e.startswith("device_tracker.lan_")]
        assert found 