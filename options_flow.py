from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    DOMAIN,
    # webhook registration
    CONF_NOTIFY_PORT,
    CONF_NOTIFY_CERT_PEM,
    # user notifications
    CONF_NOTIFY_ENABLED,
    CONF_NOTIFY_SERVICE,
    CONF_NOTIFY_CODE_OFF,
    CONF_NOTIFY_CODE_ON,
    CONF_NOTIFY_CODE_REBOOT,
)

DEFAULTS = {
    CONF_NOTIFY_ENABLED: True,            # enabled by default; uses notify.notify
    CONF_NOTIFY_SERVICE: "notify.notify",
    CONF_NOTIFY_CODE_OFF: True,
    CONF_NOTIFY_CODE_ON: True,
    CONF_NOTIFY_CODE_REBOOT: True,
}

# NOTE: Use OptionsFlowWithConfigEntry and call super().__init__(config_entry)
class RebooterOptionsFlowHandler(config_entries.OptionsFlowWithConfigEntry):
    """Options for webhook registration + user notifications."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        super().__init__(config_entry)

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            # Saving options triggers the update_listener in __init__.py (re-register webhook)
            return self.async_create_entry(title="", data=user_input)

        opts = {**DEFAULTS, **self.config_entry.options}

        # IMPORTANT:
        # - notify_port is a STRING here (blank "" allowed). We parse it later in __init__.py.
        schema = vol.Schema({
            # ---- Notifications to the device (register webhook) ----
            vol.Optional(CONF_NOTIFY_PORT, default=opts.get(CONF_NOTIFY_PORT, "")): str,
            vol.Optional(CONF_NOTIFY_CERT_PEM, default=opts.get(CONF_NOTIFY_CERT_PEM, "")): str,

            # ---- User push notifications (mobile/others) ----
            vol.Optional(CONF_NOTIFY_ENABLED, default=opts[CONF_NOTIFY_ENABLED]): bool,
            vol.Optional(CONF_NOTIFY_SERVICE, default=opts[CONF_NOTIFY_SERVICE]): str,  # "notify.notify" or "notify.mobile_app_..."
            vol.Optional(CONF_NOTIFY_CODE_OFF, default=opts[CONF_NOTIFY_CODE_OFF]): bool,
            vol.Optional(CONF_NOTIFY_CODE_ON, default=opts[CONF_NOTIFY_CODE_ON]): bool,
            vol.Optional(CONF_NOTIFY_CODE_REBOOT, default=opts[CONF_NOTIFY_CODE_REBOOT]): bool,
        })

        return self.async_show_form(step_id="init", data_schema=schema)
