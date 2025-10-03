from __future__ import annotations

from aiohttp import web

import logging
import re
from urllib.parse import urlparse
from typing import Any

import voluptuous as vol

from .ssl_utils import get_aiohttp_ssl

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.components import webhook
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_VERIFY_SSL
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    SIGNAL_UPDATE,
    # webhook registration opts
    CONF_NOTIFY_PORT,
    CONF_NOTIFY_CERT_PEM,
    # user notifications opts
    CONF_NOTIFY_ENABLED,
    CONF_NOTIFY_SERVICE,
    CONF_NOTIFY_CODE_OFF,
    CONF_NOTIFY_CODE_ON,
    CONF_NOTIFY_CODE_REBOOT,
    # codes
    CODE_OFF,
    CODE_ON,
    CODE_REBOOTING,
)

# Add more platforms as you implement them (sensor/update/etc.)
PLATFORMS = ["switch", "button"]

_LOGGER = logging.getLogger(__name__)


# ---------- Helpers ----------

def _serial_from_entry_and_data(entry: ConfigEntry, data: dict[str, Any]) -> str:
    """Prefer the config-entry unique_id (digits), else parse trailing digits from payload 'device'."""
    uid = (entry.unique_id or "").strip()
    if uid.isdigit():
        return uid
    dev = (data.get("device") or "").strip()
    m = re.search(r"(\d+)$", dev)
    if m:
        return m.group(1)
    return uid or dev  # last-resort fallback


def _normalize_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Map the device JSON into flat keys our entities use."""
    code = int(raw.get("code", 0) or 0)
    updates: dict[str, Any] = {}

    if code == CODE_OFF:
        updates["outlet_active"] = False
        updates["rebooting"] = False
    elif code == CODE_ON:
        updates["outlet_active"] = True
        updates["rebooting"] = False
    elif code == CODE_REBOOTING:
        # Leave outlet_active unchanged; mark rebooting flag for UI.
        updates["rebooting"] = True

    # Always attach last_event for visibility/automations
    updates["last_event"] = {
        "device": raw.get("device"),
        "code": code,
        "source": raw.get("source"),
        "message": raw.get("message"),
        "timestamp": dt_util.utcnow().isoformat(),
    }
    return updates


def _service_from_string(s: str) -> tuple[str, str]:
    """Split a service string like 'notify.notify' into ('notify', 'notify')."""
    s = (s or "").strip()
    if "." in s:
        domain, service = s.split(".", 1)
        return domain, service
    # Assume notify domain if user typed only the service name
    return "notify", s or "notify"


async def _register_webhook(hass: HomeAssistant, entry: ConfigEntry) -> tuple[str, str]:
    """Register (or reuse) a stable webhook for this entry and return (id, url)."""
    wh_id = entry.data.get("webhook_id")
    if not wh_id:
        wh_id = webhook.async_generate_id()
        hass.config_entries.async_update_entry(entry, data={**entry.data, "webhook_id": wh_id})

    async def handle_webhook(hass, webhook_id, request):
        # Parse JSON safely
        try:
            data = await request.json()
        except Exception as e:
            _LOGGER.debug("Webhook %s: invalid JSON (%s)", webhook_id, e)
            return web.Response(status=400, text="Invalid JSON")

        # Map webhook_id -> config entry (with fallback scan)
        domain_store = hass.data.setdefault(DOMAIN, {})
        entry_id = domain_store.get("webhook_to_entry", {}).get(webhook_id)

        if not entry_id:
            # Fallback: find which entry store advertises this webhook_id
            for eid, s in domain_store.items():
                if isinstance(s, dict) and s.get("webhook_id") == webhook_id:
                    entry_id = eid
                    domain_store.setdefault("webhook_to_entry", {})[webhook_id] = eid
                    break

        if not entry_id:
            return web.Response(status=404, text="Unknown webhook")

        # Normalize payload based on code 1/2/3
        code = data.get("code")
        try:
            code = int(code) if code is not None else None
        except (TypeError, ValueError):
            code = None


        # Check if we are inside the mute window for this entry
        domain_store = hass.data.setdefault(DOMAIN, {})
        entry_store = domain_store.get(entry_id, {})
        mute_until = entry_store.get("mute_until")

        mute_active = False
        if mute_until is not None:
            try:
                # dt_util.utcnow() is timezone-aware; stored value is too
                mute_active = dt_util.utcnow() < mute_until
            except Exception:
                mute_active = False


        # Choose the attribution for notifications:
        # - If we're inside the mute window and we have a last_actor (HA user), and the source was "App", use last actor.
        # - Otherwise, fall back to the device-provided "source".
        actor = entry_store.get("last_actor")
        via_str = f"Home Assistant — {actor}" if (mute_active and actor and (data.get("source") or "n/a")=="App") else (data.get("source", "n/a"))
        
        # ---- Optional built-in push notifications (respects user options)
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry is not None:
            opts = entry.options or {}
            notify_enabled = opts.get(CONF_NOTIFY_ENABLED, True)  # default ON
            if notify_enabled and code in (CODE_OFF, CODE_ON, CODE_REBOOTING):
                should = (
                    (code == CODE_OFF and opts.get(CONF_NOTIFY_CODE_OFF, True)) or
                    (code == CODE_ON and opts.get(CONF_NOTIFY_CODE_ON, True)) or
                    (code == CODE_REBOOTING and opts.get(CONF_NOTIFY_CODE_REBOOT, True))
                )
                if should:
                    notify_service_str = opts.get(CONF_NOTIFY_SERVICE, "notify.notify")
                    domain, service = _service_from_string(notify_service_str)
                    code_text = {
                        CODE_OFF: "turned OFF",
                        CODE_ON: "turned ON",
                        CODE_REBOOTING: "is REBOOTING",
                    }.get(code, "changed")
                    serial = _serial_from_entry_and_data(entry, data)
                    device_name = f"Rebooter Pro {serial}" if serial else (entry.title or "Rebooter Pro")
                    notify_payload = {
                        "title": f"Rebooter Pro {code_text}",
                        "message": f"{device_name} {data.get('message', '')} via {via_str}",
                    }

                    try:
                        await hass.services.async_call(domain, service, notify_payload, blocking=False)
                    except Exception:
                        _LOGGER.exception("Failed to call %s.%s for notification", domain, service)

        payload: dict[str, Any] = {}

        # Pure mute: ignore code 1/2 state flips during the window
        if not (mute_active and code in (CODE_OFF, CODE_ON) and (data.get("source") or "n/a") == "App"):
            if code == CODE_OFF:
                payload["outlet_active"] = False
                payload["rebooting"] = False
            elif code == CODE_ON:
                payload["outlet_active"] = True
                payload["rebooting"] = False
        

        if code == CODE_REBOOTING:
            payload["rebooting"] = True  # leave outlet_active unchanged

        # Always pass through last_event for attributes
        payload["last_event"] = {
            "device": data.get("device"),
            "code": code,
            "source": data.get("source"),
            "message": data.get("message"),
            "timestamp": data.get("timestamp") or dt_util.utcnow().isoformat(),
        }

        # Dispatch on the event loop (thread-safe)
        async_dispatcher_send(hass, f"{SIGNAL_UPDATE}_{entry_id}", payload)

        return web.Response(status=200, text="OK")

    # Register handler (idempotent by id)
    webhook.async_register(hass, DOMAIN, "Rebooter Pro", wh_id, handle_webhook)
    wh_url = webhook.async_generate_url(hass, wh_id)
    
    domain_store = hass.data.setdefault(DOMAIN, {})
    entry_store = domain_store.setdefault(entry.entry_id, {})
    entry_store["webhook_id"] = wh_id
    domain_store.setdefault("webhook_to_entry", {})[wh_id] = entry.entry_id
    
    _LOGGER.debug("Webhook registered: id=%s url=%s", wh_id, wh_url)
    return wh_id, wh_url


async def _push_webhook_to_device(hass: HomeAssistant, entry: ConfigEntry, wh_url: str) -> None:
    """POST the HA webhook to the device using the device's JSON shape.

    Payload schema expected by device:
      { "url": "<webhook_url>", "port": <int>, "cert": "<PEM or empty>" }
    """
    host = entry.data[CONF_HOST]
    port = entry.data.get(CONF_PORT, 443)
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)

    # Options: notify port & optional PEM to send to device
    notify_port_opt = entry.options.get(CONF_NOTIFY_PORT)
    notify_cert_pem = entry.options.get(CONF_NOTIFY_CERT_PEM) or ""

    # Derive default port from webhook URL if not set by user
    parsed = urlparse(wh_url)
    derived_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    notify_port = int(notify_port_opt) if notify_port_opt not in (None, "") else derived_port

    payload = {"url": wh_url, "port": notify_port, "cert": notify_cert_pem}

    base = f"https://{host}:{port}"
    session = async_get_clientsession(hass)
    ssl_ctx = await get_aiohttp_ssl(hass, entry)

    _LOGGER.debug(
        "Posting webhook to device %s:%s payload=%s verify_ssl=%s",
        host,
        port,
        payload,
        verify_ssl,
    )

    async with session.post(f"{base}/notify", json=payload, ssl=ssl_ctx, timeout=10) as r:
        body = await r.text()
        _LOGGER.debug("Device responded %s: %s", r.status, body[:500])
        r.raise_for_status()


async def _options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Re-register webhook with device when options change."""
    try:
        _, wh_url = await _register_webhook(hass, entry)
        await _push_webhook_to_device(hass, entry, wh_url)
        _LOGGER.info("Re-registered webhook with device at %s", entry.data.get(CONF_HOST))
    except Exception as exc:
        _LOGGER.warning("Failed to re-register webhook with device: %s", exc)


# ---------- HA entry points ----------

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the integration from a config entry."""
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"state": {}}

    # Create + register webhook, then push it to the device
    _, wh_url = await _register_webhook(hass, entry)
    try:
        await _push_webhook_to_device(hass, entry, wh_url)
    except Exception as exc:
        _LOGGER.warning("Could not register webhook with device now: %s", exc)

    # Load platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Re-register with device whenever options are saved
    entry.async_on_unload(entry.add_update_listener(_options_updated))

    # ---- Register domain service: send_test_notification (once) ----
    if not hass.data[DOMAIN].get("svc_registered"):
        async def _resolve_entry(target_entry_id: str | None) -> ConfigEntry | None:
            """Find the target entry. If not provided and only one exists, use it."""
            if target_entry_id:
                e = hass.config_entries.async_get_entry(target_entry_id)
                return e if e and e.domain == DOMAIN else None
            entries = hass.config_entries.async_entries(DOMAIN)
            return entries[0] if len(entries) == 1 else None

        async def _svc_send_test_notification(call: ServiceCall):
            target_entry_id = call.data.get("entry_id")
            title = call.data.get("title") or "Rebooter Pro Test"
            code = call.data.get("code")
            if code in (CODE_OFF, CODE_ON, CODE_REBOOTING):
                code_text = {CODE_OFF: "turned OFF", CODE_ON: "turned ON", CODE_REBOOTING: "is REBOOTING"}[code]
                default_msg = f"Test: code {code} ({code_text})"
            else:
                default_msg = "Test notification from Rebooter Pro integration."
            message = call.data.get("message") or default_msg

            target_entry = await _resolve_entry(target_entry_id)
            if not target_entry:
                _LOGGER.warning(
                    "send_test_notification: ambiguous or invalid 'entry_id'. "
                    "Provide 'entry_id' when multiple Rebooter Pro devices are configured."
                )
                return

            # Use the configured notify service for that entry (default notify.notify)
            opts = target_entry.options or {}
            notify_service_str = opts.get(CONF_NOTIFY_SERVICE, "notify.notify")
            domain, service = _service_from_string(notify_service_str)
            data = {"title": title, "message": message}
            try:
                await hass.services.async_call(domain, service, data, blocking=False)
                _LOGGER.debug("Sent test notification via %s.%s: %s", domain, service, data)
            except Exception:
                _LOGGER.exception("Failed to call %s.%s for test notification", domain, service)

        hass.services.async_register(
            DOMAIN,
            "send_test_notification",
            _svc_send_test_notification,
            schema=vol.Schema(
                {
                    vol.Optional("entry_id"): str,
                    vol.Optional("title"): str,
                    vol.Optional("message"): str,
                    vol.Optional("code"): int,  # 1,2,3 will auto-format a default message if not provided
                }
            ),
        )
        hass.data[DOMAIN]["svc_registered"] = True

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        wh_id = entry.data.get("webhook_id")
        if wh_id:
            webhook.async_unregister(hass, wh_id)
            hass.data.get(DOMAIN, {}).get("webhook_to_entry", {}).pop(wh_id, None)
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
