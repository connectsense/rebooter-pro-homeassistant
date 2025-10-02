from __future__ import annotations

import logging
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.const import CONF_HOST, CONF_PORT

from .const import DOMAIN, SIGNAL_UPDATE
from .ssl_utils import get_aiohttp_ssl

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities):
    async_add_entities([RebooterOutletSwitch(hass, entry)])


class RebooterOutletSwitch(SwitchEntity):
    _attr_name = "Toggle Outlet"

    def __init__(self, hass: HomeAssistant, entry):
        self.hass = hass
        self.entry = entry
        self._is_on = None
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
    def is_on(self) -> bool | None:
        return self._is_on

    @property
    def available(self) -> bool:
        # You could add smarter availability later; for now assume reachable.
        return True

    @property
    def extra_state_attributes(self):
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
        # Listen for webhook-driven updates
        self._unsub = async_dispatcher_connect(
            self.hass,
            f"{SIGNAL_UPDATE}_{self.entry.entry_id}",
            self._handle_push,
        )

        # One-shot seed: fetch current outlet state via GET /control
        # Run as a background task so we don't block entity setup.
        self.hass.async_create_task(self._fetch_initial_state())

    async def async_will_remove_from_hass(self):
        if self._unsub:
            self._unsub()
            self._unsub = None

    def _handle_push(self, payload: dict):
        # Update from webhook
        if "outlet_active" in payload:
            self._is_on = bool(payload["outlet_active"])
            _LOGGER.debug("Push update -> outlet_active=%s", self._is_on)
        self.async_write_ha_state()

    async def _fetch_initial_state(self):
        host = self.entry.data[CONF_HOST]
        port = self.entry.data.get(CONF_PORT, 443)
        base = f"https://{host}:{port}"

        ssl_ctx = await get_aiohttp_ssl(self.hass, self.entry)
        session = async_get_clientsession(self.hass)

        try:
            async with session.get(f"{base}/control", ssl=ssl_ctx, timeout=8) as r:
                data = await r.json(content_type=None)
                if isinstance(data, dict) and "outlet_active" in data:
                    self._is_on = bool(data["outlet_active"])
                    _LOGGER.debug("Seeded initial outlet_active=%s from GET /control", self._is_on)
                    self.async_write_ha_state()
                else:
                    _LOGGER.debug("GET /control returned unexpected payload: %s", data)
        except Exception as exc:
            _LOGGER.debug("Initial GET /control failed (%s); leaving state unknown", exc)

    async def async_turn_on(self, **kwargs):
        await self._post_control({"outlet_active": True})

    async def async_turn_off(self, **kwargs):
        await self._post_control({"outlet_active": False})

    async def _post_control(self, body: dict):
        host = self.entry.data[CONF_HOST]
        port = self.entry.data.get(CONF_PORT, 443)
        base = f"https://{host}:{port}"

        ssl_ctx = await get_aiohttp_ssl(self.hass, self.entry)
        session = async_get_clientsession(self.hass)

        _LOGGER.debug("POST /control -> %s", body)
        async with session.post(f"{base}/control", json=body, ssl=ssl_ctx, timeout=8) as r:
            resp = await r.text()
            _LOGGER.debug("Device responded %s: %s", r.status, resp[:300])
            r.raise_for_status()
