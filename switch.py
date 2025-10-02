from __future__ import annotations

import logging

from .ssl_utils import get_aiohttp_ssl

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo   # <-- change
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_VERIFY_SSL

from .const import DOMAIN, SIGNAL_UPDATE

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities):
    async_add_entities([RebooterOutletSwitch(hass, entry)])


class RebooterOutletSwitch(SwitchEntity):
    _attr_name = "Rebooter Outlet"

    def __init__(self, hass: HomeAssistant, entry):
        self.hass = hass
        self.entry = entry
        self._is_on = False
        self._unsub = None
        base_uid = entry.unique_id or entry.entry_id
        self._attr_unique_id = f"{base_uid}_outlet"
    
    @property
    def device_info(self) -> DeviceInfo:
        host = self.entry.data[CONF_HOST]
        uid = self.entry.unique_id or host
        return DeviceInfo(
            identifiers={(DOMAIN, uid)},
            name=self.entry.title or f"Rebooter Pro {uid}",
            manufacturer="Grid Connect",
            model="Rebooter Pro"
        )
        
    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def available(self) -> bool:
        return True

    @property
    def extra_state_attributes(self):
        # Expose latest event metadata for visibility in HA UI
        state = self.hass.data[DOMAIN][self.entry.entry_id]["state"]
        last = state.get("last_event") or {}
        rebooting = state.get("rebooting")
        attrs = {}
        if last:
            attrs["last_event_code"] = last.get("code")
            attrs["last_event_source"] = last.get("source")
            attrs["last_event_message"] = last.get("message")
            attrs["last_event_device"] = last.get("device")
            attrs["last_event_ts"] = last.get("timestamp")
        if rebooting is not None:
            attrs["rebooting"] = rebooting
        return attrs

    async def async_added_to_hass(self):
        # Seed from cache if available
        state = self.hass.data[DOMAIN][self.entry.entry_id]["state"]
        if "outlet_active" in state:
            self._is_on = bool(state["outlet_active"])

        self._unsub = async_dispatcher_connect(
            self.hass,
            f"{SIGNAL_UPDATE}_{self.entry.entry_id}",
            self._handle_push,
        )

    async def async_will_remove_from_hass(self):
        if self._unsub:
            self._unsub()
            self._unsub = None

    def _handle_push(self, payload: dict):
        # Update switch if present; always write state so attributes refresh (e.g., code 3)
        if "outlet_active" in payload:
            self._is_on = bool(payload["outlet_active"])
            _LOGGER.debug("Push update -> outlet_active=%s", self._is_on)
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs):
        await self._post_control({"outlet_active": True})

    async def async_turn_off(self, **kwargs):
        await self._post_control({"outlet_active": False})

    async def _post_control(self, body: dict):
        host = self.entry.data[CONF_HOST]
        port = self.entry.data.get(CONF_PORT, 443)
        verify_ssl = self.entry.data.get(CONF_VERIFY_SSL, True)
        base = f"https://{host}:{port}"

        session = async_get_clientsession(self.hass)
        ssl_ctx = await get_aiohttp_ssl(self.hass, self.entry)

        _LOGGER.debug("POST /control -> %s", body)
        async with session.post(f"{base}/control", json=body, ssl=ssl_ctx, timeout=8) as r:
            resp = await r.text()
            _LOGGER.debug("Device responded %s: %s", r.status, resp[:300])
            r.raise_for_status()
