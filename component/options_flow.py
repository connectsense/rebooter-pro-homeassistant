from __future__ import annotations

import re
import voluptuous as vol
from typing import Any

import logging
_LOGGER = logging.getLogger(__name__)

from .ssl_utils import get_aiohttp_ssl

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST

from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    SelectOptionDict,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector, 
    TextSelectorConfig, 
    TextSelectorType,
)

from .const import (
    # user notifications
    CONF_NOTIFY_ENABLED,
    CONF_NOTIFY_SERVICE,
    CONF_NOTIFY_CODE_OFF,
    CONF_NOTIFY_CODE_ON,
    CONF_NOTIFY_CODE_REBOOT,
    # automatic reboot options
    CONF_AR_POWER_FAIL,
    CONF_AR_PING_FAIL,
    CONF_AR_TRIGGER_MIN,
    CONF_AR_DELAY_MIN,
    CONF_AR_ANY_FAIL,
    CONF_AR_MAX_REBOOTS,
    CONF_AR_TARGET_1, 
    CONF_AR_TARGET_2, 
    CONF_AR_TARGET_3, 
    CONF_AR_TARGET_4, 
    CONF_AR_TARGET_5,
    CONF_AR_OFF_SECONDS,
    DEFAULT_AR_POWER_FAIL,
    DEFAULT_AR_PING_FAIL,
    DEFAULT_AR_TRIGGER_MIN,
    DEFAULT_AR_DELAY_MIN,
    DEFAULT_AR_ANY_FAIL,
    DEFAULT_AR_MAX_REBOOTS,
    DEFAULT_AR_OFF_SECONDS,
)

# strip only leading http/https (case-insensitive)
_SCHEME_RE = re.compile(r"^\s*https?://", re.IGNORECASE)

DEFAULTS_AR = {
    CONF_AR_POWER_FAIL: DEFAULT_AR_POWER_FAIL,
    CONF_AR_PING_FAIL: DEFAULT_AR_PING_FAIL,
    CONF_AR_TRIGGER_MIN: DEFAULT_AR_TRIGGER_MIN,
    CONF_AR_DELAY_MIN: DEFAULT_AR_DELAY_MIN,
    CONF_AR_ANY_FAIL: DEFAULT_AR_ANY_FAIL,
    CONF_AR_MAX_REBOOTS: DEFAULT_AR_MAX_REBOOTS,
    CONF_AR_OFF_SECONDS: DEFAULT_AR_OFF_SECONDS,
 }

DEFAULTS_NOTIFY = {
    CONF_NOTIFY_ENABLED: True,            # enabled by default; uses notify.notify
    CONF_NOTIFY_SERVICE: "notify.notify",
    CONF_NOTIFY_CODE_OFF: True,
    CONF_NOTIFY_CODE_ON: True,
    CONF_NOTIFY_CODE_REBOOT: True,
}

MAX_REBOOTS_OPTIONS = [
    SelectOptionDict(label=str(n), value=str(n)) for n in range(1, 10 + 1)
] + [SelectOptionDict(label="Unlimited", value="0")]

ANY_FAIL_OPTIONS = [
    SelectOptionDict(label="Any", value="any"),
    SelectOptionDict(label="All", value="all"),
]

def _norm_target(s: str | None) -> str:
    s = (s or "").strip()
    return _SCHEME_RE.sub("", s, count=1) if s else ""

class RebooterOptionsFlowHandler(config_entries.OptionsFlowWithConfigEntry):
    """Options for user notifications."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        super().__init__(config_entry)

    async def _fetch_device_config(self) -> dict[str, Any] | None:
        """GET /config from the device to prefill defaults."""
        host = self.config_entry.data[CONF_HOST]
        base = f"https://{host}:443"
        session = async_get_clientsession(self.hass)
        ssl_ctx = await get_aiohttp_ssl(self.hass, self.config_entry)
        try:
            _LOGGER.debug("_fetch_device_config calling get to %s/config", base)
            async with session.get(f"{base}/config", ssl=ssl_ctx, timeout=10) as r:
                txt = await r.text()  # always capture for diagnostics
                if r.status != 200:
                    _LOGGER.debug("GET /config %s -> %s; body=%s", host, r.status, txt[:500])
                    return None
                try:
                    # accept JSON even if Content-Type is wrong
                    data = await r.json(content_type=None)
                except Exception as e:
                    _LOGGER.debug("GET /config %s JSON decode failed: %r; body=%s", host, e, txt[:500])
                    return None
                return data if isinstance(data, dict) else None
        except Exception as e:
            _LOGGER.debug("Exception in _fetch_device_config: %r", e, exc_info=True)
            return None

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            # normalize each target slot
            for k in (CONF_AR_TARGET_1, CONF_AR_TARGET_2, CONF_AR_TARGET_3, CONF_AR_TARGET_4, CONF_AR_TARGET_5):
                user_input[k] = _norm_target(user_input.get(k))

            raw = str(user_input.get(CONF_AR_OFF_SECONDS, "")).strip()
            try:
                secs = int(raw)
            except Exception:
                secs = DEFAULT_AR_OFF_SECONDS
            secs = max(10, min(65535, secs))
            user_input[CONF_AR_OFF_SECONDS] = secs

            val_any = user_input.get(CONF_AR_ANY_FAIL)
            if isinstance(val_any, str):
                user_input[CONF_AR_ANY_FAIL] = (val_any == "any")  # store as bool in options

            val = user_input.get(CONF_AR_MAX_REBOOTS)
            if isinstance(val, str) and val.isdigit():
                user_input[CONF_AR_MAX_REBOOTS] = int(val)  # store as int in options

            return self.async_create_entry(title="", data=user_input)


        # Prefill defaults
        opts = {**DEFAULTS_AR, **DEFAULTS_NOTIFY, **self.config_entry.options}
        
        #try from device first
        device_cfg = await self._fetch_device_config()
        if device_cfg:
            # map device -> options defaults
            if "off_duration" in device_cfg:
                opts[CONF_AR_OFF_SECONDS] = int(device_cfg.get("off_duration", DEFAULTS_AR[CONF_AR_OFF_SECONDS]))

            if "max_auto_reboots" in device_cfg:
                opts[CONF_AR_MAX_REBOOTS] = int(device_cfg.get("max_auto_reboots", DEFAULTS_AR[CONF_AR_MAX_REBOOTS]))

            if "enable_power_fail_reboot" in device_cfg:
                opts[CONF_AR_POWER_FAIL] = bool(device_cfg.get("enable_power_fail_reboot", DEFAULTS_AR[CONF_AR_POWER_FAIL]))

            if "enable_ping_fail_reboot" in device_cfg:
                opts[CONF_AR_PING_FAIL] = bool(device_cfg.get("enable_ping_fail_reboot", DEFAULTS_AR[CONF_AR_PING_FAIL]))

            ping = device_cfg.get("ping_config") or {}
            if isinstance(ping, dict):
                if "any_fail_logic" in ping:
                    opts[CONF_AR_ANY_FAIL] = bool(ping.get("any_fail_logic", DEFAULTS_AR[CONF_AR_ANY_FAIL]))
                if "outage_trigger_time" in ping:
                    opts[CONF_AR_TRIGGER_MIN] = int(ping.get("outage_trigger_time", DEFAULTS_AR[CONF_AR_TRIGGER_MIN]))
                if "detection_delay" in ping:
                    opts[CONF_AR_DELAY_MIN] = int(ping.get("detection_delay", DEFAULTS_AR[CONF_AR_DELAY_MIN]))

            # --- SAFE TARGETS BLOCK (device state wins if present) ---
            for k in (CONF_AR_TARGET_1, CONF_AR_TARGET_2, CONF_AR_TARGET_3, CONF_AR_TARGET_4, CONF_AR_TARGET_5):
                opts[k] = ""
            targets = ping.get("target_addrs") if isinstance(ping, dict) else None
            if isinstance(targets, list):
                for i, k in enumerate((CONF_AR_TARGET_1, CONF_AR_TARGET_2, CONF_AR_TARGET_3, CONF_AR_TARGET_4, CONF_AR_TARGET_5)):
                    if i < len(targets):
                        opts[k] = (targets[i] or "")
            else:
                defaults = ["google.com","facebook.com","wikipedia.org","amazon.com","baidu.com"]
                for k, d in zip(
                    (CONF_AR_TARGET_1, CONF_AR_TARGET_2, CONF_AR_TARGET_3, CONF_AR_TARGET_4, CONF_AR_TARGET_5),
                    defaults,
                ):
                    opts[k] = self.config_entry.options.get(k) or d

        else:
            defaults = ["google.com","facebook.com","wikipedia.org","amazon.com","baidu.com"]
            for k, d in zip(
                (CONF_AR_TARGET_1, CONF_AR_TARGET_2, CONF_AR_TARGET_3, CONF_AR_TARGET_4, CONF_AR_TARGET_5),
                defaults,
            ):
                opts[k] = self.config_entry.options.get(k) or d

        schema = vol.Schema({
            # ---- Automatic Reboot (Detection & Timing) ----
            vol.Optional(CONF_AR_OFF_SECONDS, default=str(opts[CONF_AR_OFF_SECONDS])): 
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Optional(CONF_AR_POWER_FAIL, default=opts[CONF_AR_POWER_FAIL]): bool,
            vol.Optional(CONF_AR_PING_FAIL, default=opts[CONF_AR_PING_FAIL]): bool,
            vol.Optional(CONF_AR_TRIGGER_MIN, default=opts[CONF_AR_TRIGGER_MIN]):
                NumberSelector(NumberSelectorConfig(min=2, max=10, step=1, mode=NumberSelectorMode.BOX)),
            vol.Optional(CONF_AR_DELAY_MIN, default=opts[CONF_AR_DELAY_MIN]):
                NumberSelector(NumberSelectorConfig(min=0, max=10, step=1, mode=NumberSelectorMode.BOX)),
            vol.Optional(CONF_AR_MAX_REBOOTS, default=str(opts[CONF_AR_MAX_REBOOTS])):
                SelectSelector(SelectSelectorConfig(options=MAX_REBOOTS_OPTIONS, mode=SelectSelectorMode.DROPDOWN)),
            vol.Optional(CONF_AR_ANY_FAIL, default=("any" if bool(opts[CONF_AR_ANY_FAIL]) else "all")):
                SelectSelector(SelectSelectorConfig(options=ANY_FAIL_OPTIONS, mode=SelectSelectorMode.DROPDOWN)),

            # Five separate target inputs
            vol.Optional(CONF_AR_TARGET_1, default=opts[CONF_AR_TARGET_1]):
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Optional(CONF_AR_TARGET_2, default=opts[CONF_AR_TARGET_2]):
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Optional(CONF_AR_TARGET_3, default=opts[CONF_AR_TARGET_3]):
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Optional(CONF_AR_TARGET_4, default=opts[CONF_AR_TARGET_4]):
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Optional(CONF_AR_TARGET_5, default=opts[CONF_AR_TARGET_5]):
                TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),

            # ---- User push notifications (mobile/others) ----
            vol.Optional(CONF_NOTIFY_ENABLED, default=opts[CONF_NOTIFY_ENABLED]): bool,
            vol.Optional(CONF_NOTIFY_SERVICE, default=opts[CONF_NOTIFY_SERVICE]): str,
            vol.Optional(CONF_NOTIFY_CODE_OFF, default=opts[CONF_NOTIFY_CODE_OFF]): bool,
            vol.Optional(CONF_NOTIFY_CODE_ON, default=opts[CONF_NOTIFY_CODE_ON]): bool,
            vol.Optional(CONF_NOTIFY_CODE_REBOOT, default=opts[CONF_NOTIFY_CODE_REBOOT]): bool,
        })

        return self.async_show_form(step_id="init", data_schema=schema)


async def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> RebooterOptionsFlowHandler:
    """Return the options flow handler."""
    return RebooterOptionsFlowHandler(config_entry)
