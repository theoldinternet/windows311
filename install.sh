#!/usr/bin/env bash
set -euo pipefail

# ── windows311 install script ─────────────────────────────────────────────────
# Deploys the app behind nginx using gunicorn + systemd.
# Run as root (or with sudo).
#
# Usage:
#   sudo bash install.sh [domain-or-IP]
#
# Example:
#   sudo bash install.sh windows311.example.com
#   sudo bash install.sh 192.168.1.100        # bare IP
#   sudo bash install.sh                       # defaults to _ (catch-all)
# ─────────────────────────────────────────────────────────────────────────────

SERVER_NAME="${1:-_}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="${SUDO_USER:-$(logname 2>/dev/null || echo www-data)}"
SERVICE_NAME="windows311"
VENV_DIR="$APP_DIR/.venv"
SOCKET_PATH="/run/${SERVICE_NAME}.sock"
NGINX_CONF="/etc/nginx/sites-available/${SERVICE_NAME}"
NGINX_ENABLED="/etc/nginx/sites-enabled/${SERVICE_NAME}"

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
err()   { echo -e "\033[1;31m[ERR ]\033[0m  $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || err "Please run with sudo: sudo bash $0"
}

# ── 1. System packages ────────────────────────────────────────────────────────
install_packages() {
    info "Installing system packages..."
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        nginx \
        certbot python3-certbot-nginx \
        curl
    ok "System packages ready."
}

# ── 2. Python venv + dependencies ─────────────────────────────────────────────
setup_venv() {
    info "Setting up Python virtual environment in $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    "$VENV_DIR/bin/pip" install flask gunicorn -q
    ok "Python environment ready."
}

# ── 3. Systemd service ────────────────────────────────────────────────────────
create_service() {
    info "Creating systemd service: $SERVICE_NAME ..."

    # Ensure socket directory is writable by the service user
    install -d -m 755 /run

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=windows311 Flask app (gunicorn)
After=network.target

[Service]
User=${APP_USER}
Group=www-data
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_DIR}/bin"
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --workers 2 \\
    --bind unix:${SOCKET_PATH} \\
    --umask 007 \\
    --access-logfile /var/log/${SERVICE_NAME}/access.log \\
    --error-logfile  /var/log/${SERVICE_NAME}/error.log \\
    app:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p "/var/log/${SERVICE_NAME}"
    chown "${APP_USER}:www-data" "/var/log/${SERVICE_NAME}"

    # Ensure the app directory is accessible by the service user
    chown -R "${APP_USER}:www-data" "$APP_DIR"
    chmod -R u=rwX,g=rX,o= "$APP_DIR"

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}.service"
    ok "Systemd service running."
}

# ── 4. Nginx config ───────────────────────────────────────────────────────────
create_nginx_config() {
    info "Writing nginx config for server_name: $SERVER_NAME ..."

    cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name ${SERVER_NAME};

    # Increase buffer sizes for the BASIC interpreter responses
    proxy_buffer_size          16k;
    proxy_buffers              8 16k;

    # Static files served directly by nginx
    location /static/ {
        alias ${APP_DIR}/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass         http://unix:${SOCKET_PATH};
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
EOF

    # Enable site
    ln -sf "$NGINX_CONF" "$NGINX_ENABLED"

    # Remove default site if it exists and would conflict
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        info "Disabling nginx default site."
        rm -f /etc/nginx/sites-enabled/default
    fi

    nginx -t
    systemctl reload nginx
    ok "Nginx configured and reloaded."
}

# ── 5. Let's Encrypt HTTPS ────────────────────────────────────────────────────
_is_real_domain() {
    # Returns true if SERVER_NAME looks like a hostname (not _ or a bare IP)
    [[ "$SERVER_NAME" != "_" ]] && \
    [[ ! "$SERVER_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

enable_https() {
    if ! _is_real_domain; then
        info "Skipping HTTPS — no domain name provided."
        return
    fi

    info "Requesting Let's Encrypt certificate for $SERVER_NAME ..."
    certbot --nginx \
        --non-interactive \
        --agree-tos \
        --redirect \
        --email "admin@${SERVER_NAME#*.}" \
        -d "$SERVER_NAME"
    ok "HTTPS enabled. Certificate will auto-renew via certbot's systemd timer."
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    require_root
    info "Installing windows311 from: $APP_DIR"
    info "Service user: $APP_USER"
    info "Nginx server_name: $SERVER_NAME"
    echo

    install_packages
    setup_venv
    create_service
    create_nginx_config
    enable_https

    echo
    ok "Installation complete!"
    echo
    echo "  App logs:   journalctl -u ${SERVICE_NAME} -f"
    echo "  Access log: /var/log/${SERVICE_NAME}/access.log"
    echo "  Error log:  /var/log/${SERVICE_NAME}/error.log"
}

main "$@"
