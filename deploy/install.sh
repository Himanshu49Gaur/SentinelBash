#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Production Deployment & Systemd Installer
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

log_info()    { echo -e "${CYAN}[INSTALL]${RESET} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $1" >&2; }

if [[ "$(id -u)" -ne 0 ]]; then
    log_error "This script must be executed as root (e.g. sudo bash deploy/install.sh)"
    exit 1
fi

INSTALL_DIR="${SENTINEL_INSTALL_DIR:-/opt/sentinelbash}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

log_info "Deploying SentinelBash from '${SOURCE_DIR}' to '${INSTALL_DIR}'..."

# 1. System packages check / install
if command -v apt-get >/dev/null 2>&1; then
    log_info "Detected Debian/Ubuntu system. Updating and installing dependencies..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3 python3-venv python3-pip sqlite3 iptables curl jq
elif command -v dnf >/dev/null 2>&1; then
    log_info "Detected RHEL/Fedora system. Installing dependencies..."
    dnf install -y -q python3 python3-pip sqlite iptables curl jq
fi

# 2. Service User Creation
if ! id -u sentinel >/dev/null 2>&1; then
    log_info "Creating system service user 'sentinel'..."
    useradd -r -s /usr/sbin/nologin -d "${INSTALL_DIR}" sentinel
fi

# 3. Directory Structure Setup
log_info "Creating directories in ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"/{bin,config,server,static,data,data/logs,data/incidents,data/run,deploy}

# 4. Copy Codebase
log_info "Synchronizing application assets..."
cp -r "${SOURCE_DIR}/bin"/* "${INSTALL_DIR}/bin/"
cp -r "${SOURCE_DIR}/config"/* "${INSTALL_DIR}/config/"
cp -r "${SOURCE_DIR}/server"/* "${INSTALL_DIR}/server/"
cp -r "${SOURCE_DIR}/static"/* "${INSTALL_DIR}/static/"
cp -r "${SOURCE_DIR}/deploy"/* "${INSTALL_DIR}/deploy/"
cp "${SOURCE_DIR}/requirements.txt" "${INSTALL_DIR}/"

chmod +x "${INSTALL_DIR}/bin"/*.sh

# 5. Python Virtual Environment Setup
log_info "Setting up Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q

# 6. Database Initialization
log_info "Initializing SQLite database schema..."
(
    cd "${INSTALL_DIR}"
    "${INSTALL_DIR}/.venv/bin/python3" server/db/init_db.py
)

# 7. Sudoers Configuration for Least-Privilege Containment
SUDOERS_FILE="/etc/sudoers.d/sentinelbash"
log_info "Configuring sudoers permissions in ${SUDOERS_FILE}..."
cat <<EOF > "${SUDOERS_FILE}"
# SentinelBash Netfilter SOAR Permissions
sentinel ALL=(root) NOPASSWD: ${INSTALL_DIR}/bin/containment.sh *
sentinel ALL=(root) NOPASSWD: /sbin/iptables, /sbin/iptables-save, /sbin/iptables-restore
sentinel ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
sentinel ALL=(root) NOPASSWD: /usr/sbin/ufw
EOF
chmod 0440 "${SUDOERS_FILE}"

# 8. Ownership and Permissions Hardening
log_info "Applying permissions..."
chown -R root:root "${INSTALL_DIR}"
chown -R sentinel:sentinel "${INSTALL_DIR}/data" "${INSTALL_DIR}/config"
chmod -R 750 "${INSTALL_DIR}/bin"
chmod 640 "${INSTALL_DIR}/config/sentinel.conf"
chmod 644 "${INSTALL_DIR}/config/whitelist.conf"
chmod 770 "${INSTALL_DIR}/data" "${INSTALL_DIR}/data/run" "${INSTALL_DIR}/data/logs" "${INSTALL_DIR}/data/incidents"

# 9. Systemd Services Installation
if [[ -d /etc/systemd/system ]]; then
    log_info "Installing systemd services..."
    cp "${INSTALL_DIR}/deploy/sentinel-engine.service" /etc/systemd/system/
    cp "${INSTALL_DIR}/deploy/sentinel-api.service" /etc/systemd/system/
    systemctl daemon-reload
    log_success "Systemd units registered: sentinel-engine.service, sentinel-api.service"
fi

cat <<'EOF'

 =========================================================================
   ___ ___ _  _ _____ ___ _  _ ___ _    ___   _   ___ _  _ 
  / __| __| \| |_   _|_ _| \| | __| |  | _ ) /_\ / __| || |
  \__ \ _|| .` | | |  | || .` | _|| |__| _ \/ _ \\__ \ __ |
  |___/___|_|\_| |_| |___|_|\_|___|____|___/_/ \_\___/_||_|
 =========================================================================
 Installation complete!

 Master Admin Credentials:
   Username: admin
   Password: AdminSentinel2026!

 Quickstart Commands:
   sudo systemctl enable --now sentinel-engine
   sudo systemctl enable --now sentinel-api

 Tactical Web Console:
   http://localhost:8000
   API Documentation: http://localhost:8000/docs
 =========================================================================
EOF
