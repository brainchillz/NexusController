#!/usr/bin/env bash
#
# Nexus Controller uninstaller. Run as root.
#
# Default: stop + remove the service and install dir, but FIRST back up the
# encrypted node registry, admin credentials, and audit log to /var/backups so
# enrolled-node tokens are never lost irrecoverably.
#
#   ./uninstall.sh            # remove, keep a backup of state, keep the user
#   ./uninstall.sh --purge    # remove everything incl. the user and state (no backup)
#
# Honors the same CONTROLLER_DIR / CONTROLLER_USER / CONTROLLER_SERVICE env vars
# as install.sh.
#
set -euo pipefail

DIR="${CONTROLLER_DIR:-/opt/nexus-controller}"
USER_NAME="${CONTROLLER_USER:-nexuscontroller}"
SERVICE="${CONTROLLER_SERVICE:-nexus-controller}"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root." >&2; exit 1; }

echo "==> stopping + disabling $SERVICE"
systemctl disable --now "$SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload

if [ "$PURGE" -eq 0 ]; then
  BK="/var/backups/nexus-controller-$(date +%Y%m%d-%H%M%S)"
  FOUND=0
  for f in controller-auth.json nodes.json audit.log; do
    if [ -f "$DIR/$f" ]; then
      mkdir -p "$BK"; cp -a "$DIR/$f" "$BK/"; FOUND=1
    fi
  done
  [ "$FOUND" -eq 1 ] && echo "==> backed up registry/auth/audit -> $BK"
fi

echo "==> removing $DIR"
rm -rf "$DIR"

if [ "$PURGE" -eq 1 ]; then
  if id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "==> removing user $USER_NAME"
    userdel "$USER_NAME" 2>/dev/null || true
  fi
  echo "Purged. Nexus Controller and all its state are gone."
else
  echo "Removed. The service user '$USER_NAME' was kept (use --purge to remove it),"
  echo "and your node registry/credentials were backed up above."
fi
