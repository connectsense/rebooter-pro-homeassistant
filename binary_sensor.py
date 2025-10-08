from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.const import CONF_HOST

from .const import DOMAIN, SIGNAL_UPDATE

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    """Set up Rebooter Pro binary sensors from a config entry."""
    store = hass.data.setdefault(DOMAIN, {}).setdefault(entry.entry_id, {})
    store.setdefault("state", {})  # ensure exists

    entities = [
        RebooterFlagBinarySensor(
            hass=hass,
            entry=entry,
            key="pf_enabled",
            name_suffix="Power Fail Auto Reboot",
            icon_on="mdi:power-plug",
            icon_off="mdi:power-plug-off",
        ),
        RebooterFlagBinarySensor(
            hass=hass,
            entry=entry,
            key="ping_enabled",
            name_suffix="Ping Fail Auto Reboot",
            icon_on="mdi:lan-check",
            icon_off="mdi:lan-disconnect",
        ),
    ]
    # Show initial state immediately
    async_add_entities(entities, True)


class RebooterFlagBinarySensor(BinarySensorEntity):
    """Binary sensor that mirrors a boolean flag from the integration state."""
    _attr_should_poll = False

    def __init__(
        self,
        *,
        hass: HomeAssistant,
        entry: ConfigEntry,
        key: str,
        name_suffix: str,
        icon_on: str,
        icon_off: str,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self._key = key
        self._name_suffix = name_suffix
        self._icon_on = icon_on
        self._icon_off = icon_off

        base_uid = entry.unique_id or entry.entry_id
        self._attr_unique_id = f"{base_uid}_{key}"
        self._attr_name = f"{entry.title} {name_suffix}"

        state = hass.data[DOMAIN][entry.entry_id].setdefault("state", {})
        self._flag = bool(state.get(key, False))

    async def async_added_to_hass(self) -> None:
        """Subscribe to dispatcher updates."""
        @callback
        def _handler(payload: dict) -> None:
            if self._key in payload:
                new_val = bool(payload[self._key])
                if new_val != self._flag:
                    self._flag = new_val
                    self.schedule_update_ha_state()

        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, f"{SIGNAL_UPDATE}_{self.entry.entry_id}", _handler
            )
        )

    @property
    def is_on(self) -> bool:
        return self._flag

    @property
    def icon(self) -> str | None:
        return self._icon_on if self._flag else self._icon_off

    @property
    def device_info(self) -> DeviceInfo:
        host = self.entry.data[CONF_HOST]
        uid = self.entry.unique_id or host
        return DeviceInfo(
            identifiers={(DOMAIN, uid)},
            name=self.entry.title or f"Rebooter Pro {uid}",
            manufacturer="Grid Connect",
            model="Rebooter Pro",
        )
