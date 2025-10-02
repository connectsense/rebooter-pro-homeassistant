from __future__ import annotations

import logging
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

def _device_matches_entry(entry: ConfigEntry, device_field: str | None) -> bool:
    """Return True if the incoming 'device' belongs to this entry.

    Device field is like 'CS-RBTR-1000001'.
    - If entry.unique_id is the serial digits (e.g., '1000001'), match by suffix.
    - If unique_id is not numeric (e.g., manual host), accept all (cannot disambiguate).
    """
    if not device_field:
        return True
    uid = entry.unique_id or ""
    if uid.isdigit():
        return device_field.endswith(uid)
    return True


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

    async def handle_webhook(hass: HomeAssistant, webhook_id: str, request):
        """Receive device notifications, normalize, emit HA event, send optional push, and update entities."""
        try:
            raw = await request.json()
        except Exception:
            return webhook.WebhookResponse(status=400, body="Invalid JSON")

        # Expected raw payload:
        # { "device": "CS-RBTR-<serial>", "code": 1|2|3, "source": "...", "message": "..." }

        device_field = (raw or {}).get("device")
        if not _device_matches_entry(entry, device_field):
            _LOGGER.debug(
                "Ignoring webhook for device=%s not matching entry unique_id=%s",
                device_field,
                entry.unique_id,
            )
            return webhook.WebhookResponse(status=200)

        # Normalize for entities
        payload = _normalize_payload(raw)
        _LOGGER.debug("Webhook payload normalized: %s", payload)

        # ---- Fire HA event for custom automations (public API) ----
        code_int = int(raw.get("code", 0) or 0)
        hass.bus.async_fire(
            f"{DOMAIN}_event",
            {
                "device": raw.get("device"),
                "code": code_int,
                "source": raw.get("source"),
                "message": raw.get("message"),
                "entry_id": entry.entry_id,
                "unique_id": entry.unique_id,
            },
        )

        # ---- Optional built-in push notifications ----
        opts = entry.options or {}
        notify_enabled = opts.get(CONF_NOTIFY_ENABLED, True)  # default ON
        if notify_enabled:
            notify_service_str = opts.get(CONF_NOTIFY_SERVICE, "notify.notify")
            # Which codes to send?
            should = (
                (code_int == CODE_OFF and opts.get(CONF_NOTIFY_CODE_OFF, True)) or
                (code_int == CODE_ON and opts.get(CONF_NOTIFY_CODE_ON, True)) or
                (code_int == CODE_REBOOTING and opts.get(CONF_NOTIFY_CODE_REBOOT, True))
            )
            if should and notify_service_str:
                domain, service = _service_from_string(notify_service_str)
                # Human text for code
                code_text = {CODE_OFF: "turned OFF", CODE_ON: "turned ON", CODE_REBOOTING: "is REBOOTING"}.get(code_int, "changed")
                data = {
                    "title": f"{raw.get('device')} ({raw.get('source','n/a')})",
                    "message": f"{raw.get('device')} {code_text} — {raw.get('message','')}",
                }
                try:
                    await hass.services.async_call(domain, service, data, blocking=False)
                except Exception:  # pragma: no cover
                    _LOGGER.exception("Failed to call %s.%s for notification", domain, service)

        # Merge into per-entry state cache
        store = hass.data[DOMAIN][entry.entry_id]
        store["state"].update(payload)

        # Notify entities bound to this entry
        async_dispatcher_send(hass, f"{SIGNAL_UPDATE}_{entry.entry_id}", payload)

        return webhook.WebhookResponse(status=200)

    # Register handler (idempotent by id)
    webhook.async_register(hass, DOMAIN, "Rebooter Pro", wh_id, handle_webhook)
    wh_url = webhook.async_generate_url(hass, wh_id)
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
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
