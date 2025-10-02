from __future__ import annotations

import ssl
from pathlib import Path
from homeassistant.const import CONF_VERIFY_SSL

# Embedded CA (your PEM file lives here)
_EMBEDDED_CA = Path(__file__).parent / "certs" / "device_ca.pem"

def _build_ctx_from_embedded_ca() -> ssl.SSLContext:
    """
    Build an SSLContext WITHOUT loading system defaults (avoids blocking calls),
    and trust only the embedded CA. Hostname checking remains enabled.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    # Only load our CA; do NOT call load_default_certs()
    ctx.load_verify_locations(cafile=str(_EMBEDDED_CA))
    return ctx

async def get_aiohttp_ssl(hass, entry):
    """
    Returns the object you should pass to aiohttp's 'ssl=' parameter:
      - False  -> disable verification (when entry.verify_ssl is False)
      - SSLContext (built in executor) -> use embedded CA
      - None   -> use aiohttp default (system trust store)
    """
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)
    if not verify_ssl:
        return False

    if _EMBEDDED_CA.exists():
        # Build the context in a worker thread to avoid blocking the loop
        return await hass.async_add_executor_job(_build_ctx_from_embedded_ca)

    # No embedded CA: let aiohttp use its default context
    return None
