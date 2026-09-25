#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Production Uninstaller & Cleanup
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[ERROR]${RESET} Must be run as root (e.g. sudo bash deploy/uninstall.sh)" >&2
    exit 1
fi

INSTALL_DIR="${SENTINEL_INSTALL_DIR:-/opt/sentinelbash}"

echo -e "${YELLOW}[UNINSTALL]${RESET} Stopping and disabling systemd services..."
systemctl stop sentinel-api 2>/dev/null || true
systemctl stop sentinel-engine 2>/dev/null || true
systemctl disable sentinel-api 2>/dev/null || true
systemctl disable sentinel-engine 2>/dev/null || true

if [[ -f /etc/systemd/system/sentinel-api.service ]]; then
    rm -f /etc/systemd/system/sentinel-api.service
fi
if [[ -f /etc/systemd/system/sentinel-engine.service ]]; then
    rm -f /etc/systemd/system/sentinel-engine.service
fi
systemctl daemon-reload 2>/dev/null || true

# Flush Netfilter rules if containment script exists
if [[ -f "${INSTALL_DIR}/bin/containment.sh" ]]; then
    echo -e "${YELLOW}[UNINSTALL]${RESET} Flushing SentinelBash firewall chains..."
    "${INSTALL_DIR}/bin/containment.sh" flush || true
fi

# Remove sudoers
if [[ -f /etc/sudoers.d/sentinelbash ]]; then
    rm -f /etc/sudoers.d/sentinelbash
fi

# Remove files
echo -e "${YELLOW}[UNINSTALL]${RESET} Removing installation directory ${INSTALL_DIR}..."
rm -rf "${INSTALL_DIR}"

# Remove user
if id -u sentinel >/dev/null 2>&1; then
    userdel sentinel 2>/dev/null || true
fi

echo -e "${GREEN}[SUCCESS]${RESET} SentinelBash completely uninstalled."
