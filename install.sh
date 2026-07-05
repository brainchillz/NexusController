#!/usr/bin/env bash
#
# Nexus Controller installer.
#
# Installs the controller as an UNPRIVILEGED systemd service: a dedicated system
# user with no login and no sudo (the controller never needs root — it only
# speaks HTTPS to nodes). Run as root from the repo directory.
#
# Idempotent: re-running upgrades in place (refreshes code + deps, restarts the
# service) and PRESERVES the encrypted node registry and admin credentials.
#
# Configurable via environment:
#   CONTROLLER_DIR             install dir            (default /opt/nexus-controller)
#   CONTROLLER_USER            service user          (default nexuscontroller)
#   CONTROLLER_SERVICE         systemd unit name     (default nexus-controller)
#   CONTROLLER_PORT            listen port           (default 9443)
#   CONTROLLER_TLS             1=HTTPS 0=HTTP        (default 1)
#   CONTROLLER_ADMIN_PASSWORD  seed admin password   (default: random, logged)
#
set -euo pipefail

DIR="${CONTROLLER_DIR:-/opt/nexus-controller}"
USER_NAME="${CONTROLLER_USER:-nexuscontroller}"
SERVICE="${CONTROLLER_SERVICE:-nexus-controller}"
PORT="${CONTROLLER_PORT:-9443}"
TLS="${CONTROLLER_TLS:-1}"
SRC="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (creates a user, $DIR, and a systemd unit)." >&2; exit 1; }
[ -f "$SRC/app.py" ] || { echo "ERROR: run from the NexusController repo dir (app.py not found)." >&2; exit 1; }

# Is this a fresh install or an in-place upgrade? (decides the password hint.)
FRESH=1; [ -f "$DIR/controller-auth.json" ] && FRESH=0

echo "==> Nexus Controller $([ "$FRESH" -eq 1 ] && echo install || echo upgrade)"
echo "    dir=$DIR  user=$USER_NAME  service=$SERVICE  port=$PORT  tls=$TLS"

# 1. Prerequisites: python3 + venv module.
command -v python3 >/dev/null || { echo "ERROR: python3 is required." >&2; exit 1; }
if ! python3 -c 'import venv' 2>/dev/null; then
  echo "==> installing python3-venv"
  apt-get update -qq && apt-get install -y python3-venv
fi

# 2. Dedicated unprivileged system user (home = install dir, no shell).
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  echo "==> creating system user $USER_NAME"
  useradd --system --home-dir "$DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi

# 3. Install app files (state files like nodes.json are not in the repo, so they
#    are never touched here — this is what makes re-running a safe upgrade).
echo "==> installing app files -> $DIR"
mkdir -p "$DIR"
cp "$SRC/app.py" "$SRC/monitoring.py" "$SRC/history.py" "$SRC/requirements.txt" "$DIR/"
rm -rf "$DIR/templates" "$DIR/static" "$DIR/adapters" "$DIR/collectors"
cp -r "$SRC/templates" "$SRC/static" "$SRC/adapters" "$SRC/collectors" "$DIR/"

# 4. Virtualenv + dependencies.
echo "==> python venv + dependencies"
[ -d "$DIR/venv" ] || python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install --quiet --upgrade pip
"$DIR/venv/bin/pip" install --quiet -r "$DIR/requirements.txt"

# 5. Ownership: the service writes nodes.json / controller-auth.json / audit.log
#    and (for TLS) certs/ inside the install dir.
chown -R "$USER_NAME":"$USER_NAME" "$DIR"
chmod 750 "$DIR"

# 6. Bootstrap the admin password deterministically when provided and no
#    credentials exist yet. Otherwise the service generates one on first start
#    and prints it to the journal.
if [ -n "${CONTROLLER_ADMIN_PASSWORD:-}" ] && [ "$FRESH" -eq 1 ]; then
  echo "==> setting initial admin password"
  sudo -u "$USER_NAME" CONTROLLER_ADMIN_PASSWORD="$CONTROLLER_ADMIN_PASSWORD" \
    "$DIR/venv/bin/python" "$DIR/app.py" set-password admin
fi

# 7. systemd unit (unprivileged + sandboxed; the controller needs no privilege).
echo "==> writing /etc/systemd/system/$SERVICE.service"
cat > "/etc/systemd/system/$SERVICE.service" <<UNIT
[Unit]
Description=Nexus Fleet Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$DIR
Environment=CONTROLLER_PORT=$PORT
Environment=CONTROLLER_TLS=$TLS
ExecStart=$DIR/venv/bin/python $DIR/app.py
Restart=on-failure
RestartSec=5
# Hardening — the controller has no need for elevated privileges.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DIR
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 2

STATE="$(systemctl is-active "$SERVICE" || true)"
echo "==> service $SERVICE: $STATE"
echo
if [ "$STATE" = "active" ]; then
  SCHEME=$([ "$TLS" = "1" ] && echo https || echo http)
  echo "Nexus Controller is up at ${SCHEME}://<this-host>:${PORT}"
  if [ "$FRESH" -eq 1 ] && [ -z "${CONTROLLER_ADMIN_PASSWORD:-}" ]; then
    echo "Admin password (generated on first start):"
    echo "  journalctl -u $SERVICE | grep -A2 'created initial admin account'"
  fi
  echo "Reset it anytime:  sudo -u $USER_NAME $DIR/venv/bin/python $DIR/app.py set-password admin"
else
  echo "Service did not start. Check: journalctl -u $SERVICE -n 50" >&2
  exit 1
fi
