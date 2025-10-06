from __future__ import annotations

from aiohttp import web

import logging
import re
from urllib.parse import urlparse
from typing import Any

import voluptuous as vol

from .ssl_utils import get_aiohttp_ssl

import secrets
from datetime import timedelta
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.components import webhook
from homeassistant.const import CONF_HOST
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    SIGNAL_UPDATE,
    ROTATE_INTERVAL,
    RETRY_INTERVAL,
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
    CONF_WEBHOOK_TOKEN_CURRENT,
    CONF_WEBHOOK_TOKEN_PREV,
    CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL,
    DEFAULT_TOKEN_GRACE_SECONDS,
)

# Add more platforms as you implement them (sensor/update/etc.)
PLATFORMS = ["switch", "button"]

_LOGGER = logging.getLogger(__name__)


# ---------- Helpers ----------

async def _ensure_tokens(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Guarantee a current token exists (prev stays None until first rotation)."""
    if not entry.data.get(CONF_WEBHOOK_TOKEN_CURRENT):
        new_tok = secrets.token_urlsafe(32)
        hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                CONF_WEBHOOK_TOKEN_CURRENT: new_tok,
                CONF_WEBHOOK_TOKEN_PREV: None,
                CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL: None,
            },
        )

def _get_allowed_ips_for_entry(hass: HomeAssistant, entry: ConfigEntry) -> set[str]:
    """Return a set of allowed source IPs for this entry (may be empty)."""
    # Prefer what config_flow saved, else an empty set (means: no enforcement)
    ips = entry.data.get("ip_addresses") or entry.data.get("ip_addrs") or []
    # Normalize strings only
    return {str(ip) for ip in ips if isinstance(ip, (str, bytes))}


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


        # Enforce IP allowlist if we have entries on file
        entry = hass.config_entries.async_get_entry(entry_id)
        allowed = _get_allowed_ips_for_entry(hass, entry) if entry else set()
        if allowed:
            src_ip = request.remote or ""
            if src_ip not in allowed:
                _LOGGER.warning("Webhook IP %s not in allowlist for %s", src_ip, entry_id)
                return web.Response(status=403, text="Forbidden")

        # Authorization header check (rotating token with grace)
        actual = request.headers.get("Authorization", "")
        cur_tok = entry.data.get(CONF_WEBHOOK_TOKEN_CURRENT) if entry else None
        prev_tok = entry.data.get(CONF_WEBHOOK_TOKEN_PREV) if entry else None
        prev_until_iso = entry.data.get(CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL) if entry else None

        def _matches(header: str, token: str | None) -> bool:
            return bool(token) and header == f"Bearer {token}"

        now = dt_util.utcnow()
        prev_ok = False
        if prev_tok and prev_until_iso:
            try:
                prev_until = dt_util.parse_datetime(prev_until_iso)
                prev_ok = prev_until is not None and now <= prev_until
            except Exception:
                prev_ok = False

        if not (_matches(actual, cur_tok) or (prev_ok and _matches(actual, prev_tok))):
            _LOGGER.warning("Webhook auth failed for %s", entry_id)  # never log tokens
            return web.Response(status=401, text="Unauthorized")


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

        # Start a token-rotation retry loop (every 5 minutes) after any valid webhook
        try:
            await _ensure_post_webhook_retry(hass, entry_id)
        except Exception as exc:
            _LOGGER.debug("Post-webhook retry setup failed: %s", exc)

        return web.Response(status=200, text="OK")

    # Register handler (idempotent): if already registered, reuse it
    try:
        webhook.async_register(hass, DOMAIN, "Rebooter Pro", wh_id, handle_webhook)
    except ValueError:
        # "Handler is already defined!" – it's fine; keep using the existing one
        _LOGGER.debug("Webhook %s already registered; reusing existing handler.", wh_id)

    wh_url = webhook.async_generate_url(hass, wh_id)
    
    domain_store = hass.data.setdefault(DOMAIN, {})
    entry_store = domain_store.setdefault(entry.entry_id, {})
    entry_store["webhook_id"] = wh_id
    domain_store.setdefault("webhook_to_entry", {})[wh_id] = entry.entry_id
    
    _LOGGER.debug("Webhook registered: id=%s url=%s", wh_id, wh_url)
    return wh_id, wh_url

async def _rotate_token_and_push(hass: HomeAssistant, entry: ConfigEntry, wh_url: str, reason: str) -> bool:
    """Rotate the per-entry token and push it to the device.
    Returns True on success (tokens updated), False on failure (unchanged)."""
    now = dt_util.utcnow()
    grace_seconds = DEFAULT_TOKEN_GRACE_SECONDS

    cur = entry.data.get(CONF_WEBHOOK_TOKEN_CURRENT)
    prev = entry.data.get(CONF_WEBHOOK_TOKEN_PREV)
    prev_until = entry.data.get(CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL)

    new_tok = secrets.token_urlsafe(32)

    # Try pushing the new token; only persist if it succeeds.
    try:
        await _push_webhook_to_device(hass, entry, wh_url, override_token=new_tok)
    except Exception as exc:
        _LOGGER.info("Token rotation skipped (push failed): %s", exc)
        return False

    # Persist rotation: current -> previous (with grace), new -> current
    prev_valid_until_iso = (now + timedelta(seconds=grace_seconds)).isoformat()
    hass.config_entries.async_update_entry(
        entry,
        data={
            **entry.data,
            CONF_WEBHOOK_TOKEN_PREV: cur,
            CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL: prev_valid_until_iso,
            CONF_WEBHOOK_TOKEN_CURRENT: new_tok,
        },
    )
    _LOGGER.debug("Rotated webhook token for %s (reason=%s); previous valid until %s", entry.entry_id, reason, prev_valid_until_iso)
    return True

def _get_entry_store(hass: HomeAssistant, entry_id: str) -> dict:
    """Convenience accessor for per-entry store."""
    return hass.data.setdefault(DOMAIN, {}).setdefault(entry_id, {})


def _cancel_retry(hass: HomeAssistant, entry_id: str) -> None:
    """Cancel an active post-webhook retry loop if present."""
    store = _get_entry_store(hass, entry_id)
    unsub = store.pop("rotate_retry_unsub", None)
    if unsub:
        try:
            unsub()
        except Exception:
            pass
        _LOGGER.debug("Stopped post-webhook rotation retry for %s", entry_id)


async def _ensure_post_webhook_retry(hass: HomeAssistant, entry_id: str) -> None:
    """Start a 5-minute retry loop to rotate the token after a webhook, until success."""
    store = _get_entry_store(hass, entry_id)
    if store.get("rotate_retry_unsub"):
        # Already running
        return

    async def _retry_tick(_now) -> None:
        entry = hass.config_entries.async_get_entry(entry_id)
        if not entry:
            _cancel_retry(hass, entry_id)
            return
        wh_id = store.get("webhook_id")
        if not wh_id:
            _cancel_retry(hass, entry_id)
            return
        wh_url = webhook.async_generate_url(hass, wh_id)
        ok = await _rotate_token_and_push(hass, entry, wh_url, reason="post-webhook")
        if ok:
            _cancel_retry(hass, entry_id)

    # Schedule retry loop
    unsub = async_track_time_interval(hass, _retry_tick, RETRY_INTERVAL)
    store["rotate_retry_unsub"] = unsub
    _LOGGER.debug("Started post-webhook rotation retry every %s for %s", RETRY_INTERVAL, entry_id)
    # Kick an immediate attempt (doesn't block the loop)
    hass.async_create_task(_retry_tick(dt_util.utcnow()))

async def _push_webhook_to_device(hass: HomeAssistant, entry: ConfigEntry, wh_url: str, override_token: str | None = None) -> None:
    """POST the HA webhook to the device using the device's JSON shape.

    Payload schema expected by device:
      { "url": "<webhook_url>", "port": <int>, "headers": {"Authorization": "Bearer <token>"}  # present only if token exists }
    """
    host = entry.data[CONF_HOST]
    port = 443

    # Choose token: override (for rotation) or current stored token
    token = override_token or entry.data.get(CONF_WEBHOOK_TOKEN_CURRENT)    

    # Derive default port from webhook URL if not set by user
    parsed = urlparse(wh_url)
    notify_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    payload = {"url": wh_url, "port": notify_port}
    if token:
        payload["headers"] = {"Authorization": f"Bearer {token}"}

    base = f"https://{host}:{port}"
    session = async_get_clientsession(hass)
    ssl_ctx = await get_aiohttp_ssl(hass, entry)

    # Redact token in logs
    if token:
        redacted = {"url": wh_url, "port": notify_port, "headers": {"Authorization": "Bearer <redacted>"}}
    else:
        redacted = {"url": wh_url, "port": notify_port}
    _LOGGER.debug("Posting webhook to device %s:%s payload=%s", host, port, redacted)

    async with session.post(f"{base}/notify", json=payload, ssl=ssl_ctx, timeout=10) as r:
        body = await r.text()
        _LOGGER.debug("Device responded %s: %s", r.status, body[:500])
        r.raise_for_status()


async def _options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    _LOGGER.debug("Options updated for %s", entry.entry_id)


# ---------- HA entry points ----------

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the Rebooter Pro integration from a config entry."""
    # Per-entry state bucket
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"state": {}}

    # Ensure a current token exists (prev/grace managed elsewhere)
    await _ensure_tokens(hass, entry)

    # Cache an IP allowlist for this entry if we discovered any
    hass.data[DOMAIN][entry.entry_id]["allow_ips"] = _get_allowed_ips_for_entry(hass, entry)

    # Create/register webhook and push it to the device with the current token
    _, wh_url = await _register_webhook(hass, entry)
    try:
        await _push_webhook_to_device(hass, entry, wh_url)
    except Exception as exc:
        _LOGGER.warning("Could not register webhook with device now: %s", exc)

    # Load platforms (switch, button, etc.)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Re-register with device whenever options change
    entry.async_on_unload(entry.add_update_listener(_options_updated))

    # --- Periodic token rotation every ROTATE_INTERVAL ---
    async def _tick(_now):
        # Rotate token and push to device on the event loop
        store = hass.data.setdefault(DOMAIN, {}).setdefault(entry.entry_id, {})
        wh_id = store.get("webhook_id") or entry.data.get("webhook_id")
        if not wh_id:
            return
        fresh_wh_url = webhook.async_generate_url(hass, wh_id)
        await _rotate_token_and_push(hass, entry, fresh_wh_url, reason="daily")

    unsub_rotate = async_track_time_interval(hass, _tick, ROTATE_INTERVAL)
    entry.async_on_unload(unsub_rotate)

    # ---- Domain service: send_test_notification (register once) ----
    if not hass.data[DOMAIN].get("svc_registered"):
        async def _resolve_entry(target_entry_id: str | None) -> ConfigEntry | None:
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
                    vol.Optional("code"): int,  # 1,2,3 will format a default message if not provided
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
