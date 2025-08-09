from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    CONF_ABSENT_AFTER,
    CONF_INTERVAL,
    CONF_SUBNETS,
    DEFAULT_ABSENT_AFTER,
    DEFAULT_INTERVAL,
    DOMAIN,
)


class LanwatchConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            # Basic validation
            subnets = [s.strip() for s in user_input[CONF_SUBNETS].split(",") if s.strip()]
            if not subnets:
                errors[CONF_SUBNETS] = "invalid_subnets"
            else:
                return self.async_create_entry(
                    title="LanWatch",
                    data={
                        CONF_SUBNETS: subnets,
                        CONF_INTERVAL: int(user_input.get(CONF_INTERVAL, DEFAULT_INTERVAL)),
                        CONF_ABSENT_AFTER: int(
                            user_input.get(CONF_ABSENT_AFTER, DEFAULT_ABSENT_AFTER)
                        ),
                    },
                )

        data_schema = vol.Schema(
            {
                vol.Required(CONF_SUBNETS, default="192.168.1.0/24"): str,
                vol.Optional(CONF_INTERVAL, default=DEFAULT_INTERVAL): int,
                vol.Optional(CONF_ABSENT_AFTER, default=DEFAULT_ABSENT_AFTER): int,
            }
        )

        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
