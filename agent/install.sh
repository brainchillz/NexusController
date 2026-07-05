#!/bin/sh
# Nexus Agent installer — drop a read-only metrics endpoint onto any Linux
# machine with python3 + systemd. Idempotent: re-run to upgrade in place
# (token + cert are preserved). Run as root from the agent/ directory.
#
#   sudo ./install.sh                     # -> /opt/nexus-agent on :9143
#   sudo AGENT_PORT=9200 ./install.sh     # custom port
#
# Uninstall:  sudo ./install.sh --uninstall
set -eu

DIR="${AGENT_DIR:-/opt/nexus-agent}"
USER_NAME="${AGENT_USER:-nexusagent}"
SERVICE="${AGENT_SERVICE:-nexus-agent}"
PORT="${AGENT_PORT:-9143}"
SRC="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (sudo ./install.sh)" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload
    echo "Service removed. Agent files (incl. token/cert) left at $DIR —"
    echo "delete with: rm -rf $DIR   (and: userdel $USER_NAME)"
    exit 0
fi

command -v python3 >/dev/null || { echo "ERROR: python3 is required" >&2; exit 1; }
[ -f "$SRC/nexus_agent.py" ] || { echo "ERROR: run from the agent/ directory" >&2; exit 1; }

echo "==> user + files -> $DIR"
id "$USER_NAME" >/dev/null 2>&1 || \
    useradd --system --home-dir "$DIR" --shell /usr/sbin/nologin "$USER_NAME" 2>/dev/null || \
    useradd -r -d "$DIR" -s /sbin/nologin "$USER_NAME"
mkdir -p "$DIR/data"
cp "$SRC/nexus_agent.py" "$DIR/"
chown -R "$USER_NAME:$USER_NAME" "$DIR"
chmod 700 "$DIR/data"

# Self-signed cert for HTTPS (once — never overwrite; the controller pins it).
if [ ! -f "$DIR/data/agent.crt" ]; then
    echo "==> generating self-signed TLS certificate"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$DIR/data/agent.key" -out "$DIR/data/agent.crt" \
        -subj "/CN=$(hostname)" >/dev/null 2>&1
    chown "$USER_NAME:$USER_NAME" "$DIR/data/agent.key" "$DIR/data/agent.crt"
    chmod 600 "$DIR/data/agent.key"
fi

echo "==> systemd unit ($SERVICE, port $PORT)"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Nexus Agent (read-only metrics endpoint)
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
Environment=AGENT_PORT=$PORT
Environment=AGENT_DATA_DIR=$DIR/data
ExecStart=/usr/bin/env python3 $DIR/nexus_agent.py
Restart=on-failure
RestartSec=5

# Hardening — the agent only reads /proc and statvfs()s mounts.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DIR/data
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 1
systemctl --no-pager --quiet is-active "$SERVICE" || {
    echo "ERROR: service failed to start:" >&2
    journalctl -u "$SERVICE" -n 10 --no-pager >&2 || true
    exit 1
}

TOKEN="$(cat "$DIR/data/token" 2>/dev/null || true)"
if [ -z "$TOKEN" ]; then
    sleep 1   # first boot mints the token
    TOKEN="$(cat "$DIR/data/token" 2>/dev/null || echo '(see: journalctl -u '"$SERVICE"')')"
fi
IP="$(hostname -I 2>/dev/null | awk '{print $1}' || hostname)"
echo
echo "Nexus Agent is running."
echo "  Enroll in the controller as host type 'Nexus Agent':"
echo "    Base URL:  https://$IP:$PORT"
echo "    Token:     $TOKEN"
