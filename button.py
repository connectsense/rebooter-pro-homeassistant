from __future__ import annotations

from .ssl_utils import get_aiohttp_ssl

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_VERIFY_SSL

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([RebooterRebootButton(hass, entry)])


class RebooterRebootButton(ButtonEntity):
    _attr_name = "Reboot Device"

    def __init__(self, hass, entry):
        self.hass = hass
        self.entry = entry
        base_uid = entry.unique_id or entry.entry_id
        self._attr_unique_id = f"{base_uid}_reboot"

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

    async def async_press(self) -> None:
        host = self.entry.data[CONF_HOST]
        port = self.entry.data.get(CONF_PORT, 443)
        verify_ssl = self.entry.data.get(CONF_VERIFY_SSL, True)
        base = f"https://{host}:{port}"

        session = async_get_clientsession(self.hass)
        ssl_ctx = await get_aiohttp_ssl(self.hass, self.entry)

        async with session.post(f"{base}/control", json={"outlet_reboot": True}, ssl=ssl_ctx, timeout=8) as r:
            r.raise_for_status()