from datetime import timedelta

DOMAIN = "rebooter_pro"

# Dispatcher signal base; we suffix with entry_id so multiple devices don't cross-talk
SIGNAL_UPDATE = "rebooter_pro_update"

# ---- Options (user notifications) ----
CONF_NOTIFY_ENABLED = "notify_enabled"          # bool
CONF_NOTIFY_SERVICE = "notify_service"          # e.g. "notify.notify" (default) or "notify.mobile_app_..."
CONF_NOTIFY_CODE_OFF = "notify_on_off"          # bool
CONF_NOTIFY_CODE_ON = "notify_on_on"            # bool
CONF_NOTIFY_CODE_REBOOT = "notify_on_reboot"    # bool

# Rebooter Pro notification codes
CODE_OFF = 1
CODE_ON = 2
CODE_REBOOTING = 3

# Token-based webhook auth (HTTP, plaintext shared secret)
CONF_WEBHOOK_TOKEN_CURRENT = "webhook_token_current"
CONF_WEBHOOK_TOKEN_PREV = "webhook_token_prev"
CONF_WEBHOOK_TOKEN_PREV_VALID_UNTIL = "webhook_token_prev_valid_until"
DEFAULT_TOKEN_GRACE_SECONDS = 120  # accept previous token for 2 minutes after rotation

# Token rotation cadence
ROTATE_INTERVAL = timedelta(days=1)       # daily rotation
RETRY_INTERVAL = timedelta(minutes=5)     # after-webhook retry cadence