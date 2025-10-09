from __future__ import annotations

import logging
import re
import ipaddress
from typing import Any
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SERIAL_RE = re.compile(r"Rebooter Pro\s+(\d+)", re.IGNORECASE)

# Only hostname is requested now
USER_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST, default="rebooter-pro.local"): str,
})


def _zget(obj: Any, attr: str, default: Any = None) -> Any:
    """Get zeroconf info attribute from either ZeroconfServiceInfo or a dict."""
    if hasattr(obj, attr):
        try:
            return getattr(obj, attr)
        except Exception:
            pass
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return default


class RebooterConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=USER_SCHEMA)

        host = (user_input.get(CONF_HOST) or "").strip()

        # If the user typed an IP, note (for logs) that TLS hostname verification should be skipped.
        # The integration should actually enforce/decide this in ssl_utils based on host being an IP.
        try:
            ipaddress.ip_address(host)
            _LOGGER.debug(
                "User entered IP '%s'; downstream SSL helper should disable hostname verification.",
                host,
            )
        except ValueError:
            # Not an IP; keep normal hostname verification downstream.
            pass

        await self.async_set_unique_id(host)
        self._abort_if_unique_id_configured(updates={CONF_HOST: host})

        data = {
            CONF_HOST: host,
        }
        return self.async_create_entry(title=f"Rebooter Pro ({host})", data=data)

    async def async_step_zeroconf(self, discovery_info: Any):
        # Handle both ZeroconfServiceInfo and dict payloads
        hostname_raw = _zget(discovery_info, "hostname") or ""
        hostname = hostname_raw.rstrip(".") if hostname_raw else ""

        # ip_addresses is a list in modern HA; older payloads may have ip_address (singular)
        ips = _zget(discovery_info, "ip_addresses") or []
        if not ips:
            single_ip = _zget(discovery_info, "ip_address")
            if single_ip:
                ips = [single_ip]

        host_attr = _zget(discovery_info, "host")  # may be None or an IP string

        # Choose host used by the integration:
        # Prefer mDNS hostname (enables TLS hostname verification downstream).
        # Otherwise, fall back to an IP (SSL helper should skip verification in that case).
        if hostname:
            host = hostname
        else:
            host = host_attr or (ips[0] if ips else None)
            _LOGGER.debug(
                "Zeroconf fallback to IP '%s'; downstream SSL helper should disable hostname verification.",
                host,
            )

        name = _zget(discovery_info, "name") or ""  # e.g. "Rebooter Pro 1010001._https._tcp.local."
        m = SERIAL_RE.search(name)
        serial = m.group(1) if m else (hostname or host or "rebooter-pro")

        await self.async_set_unique_id(str(serial))
        self._abort_if_unique_id_configured(
            updates={
                CONF_HOST: host,
            }
        )

        return self.async_create_entry(
            title=f"Rebooter Pro {serial}",
            data={
                CONF_HOST: host,
            },
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        from .options_flow import RebooterOptionsFlowHandler
        return RebooterOptionsFlowHandler(config_entry)
