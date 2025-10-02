DOMAIN = "rebooter_pro"

# Dispatcher signal base; we suffix with entry_id so multiple devices don't cross-talk
SIGNAL_UPDATE = "rebooter_pro_update"

# ---- Options (webhook registration) ----
CONF_NOTIFY_PORT = "notify_port"
CONF_NOTIFY_CERT_PEM = "notify_cert_pem"

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
