# SentinelBash: High-Performance Autonomous SOC & Incident Response Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Engine: Pure Bash & POSIX](https://img.shields.io/badge/Core-POSIX%20Bash-4EAA25?logo=gnu-bash&logoColor=white)](bin/)
[![API: FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](server/)
[![Database: SQLite WAL](https://img.shields.io/badge/Storage-SQLite%20WAL-003B57?logo=sqlite&logoColor=white)](server/db/)
[![Firewall: Netfilter / iptables](https://img.shields.io/badge/SOAR-Netfilter%20%2F%20iptables-E95420?logo=linux&logoColor=white)](bin/containment.sh)
[![Architecture: Dual--Engine](https://img.shields.io/badge/Architecture-Dual--Engine%20Hybrid-7928CA)](APP_FLOW.md)
[![Tests: 100% Automated](https://img.shields.io/badge/Tests-Passing%20(70%2B%20Specs)-brightgreen)](tests/)

> **Autonomous cyber defense, real-time threat detection, and sub-second Netfilter containment engineered in POSIX Bash, backed by SQLite WAL persistence and an Obsidian glass SOC management console.**

---

## 1. Executive Summary

**SentinelBash** is an enterprise-grade Security Operations Center (SOC) automation and Security Orchestration, Automation, and Response (SOAR) platform. It bridges the speed and zero-dependency footprint of low-level Linux kernel netfilter tooling with the ergonomics, audibility, and visualization of modern cyber defense web consoles.

### Why SentinelBash?
Enterprise SIEMs and SOAR platforms (Splunk ES, Palo Alto Cortex XSOAR, IBM QRadar) are frequently bottlenecked by heavy runtime overhead, complex agent deployments, and multi-second execution delays. **SentinelBash** demonstrates how high-velocity security automation can be achieved with sub-second MTTR (Mean Time to Respond) using standard Unix process pipelines, sliding-window streaming state, and atomic kernel netfilter manipulation.

```
+-----------------------------------------------------------------------------------------+
|                               SENTINELBASH ARCHITECTURE                                 |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   [ Linux System Logs ]                                                                 |
|   /var/log/auth.log, /var/log/nginx/access.log, syslog                                  |
|            │                                                                            |
|            ▼                                                                            |
|   [ Ingestion Layer ] ──> FIFO Buffer ──> Stream Normalization (JSON Events)            |
|   bin/ingestor.sh                                                                       |
|            │                                                                            |
|            ▼                                                                            |
|   [ Detection Engine ] ──> Sliding-Window Bucket Analysis (O(1) Ring Aggregations)      |
|   bin/detector.sh          - SSH Brute Force (Threshold: 5 attempts / 60s)              |
|                            - Web Probes (Traversal, SQLi, .env, nikto)                  |
|                            - Privilege Escalation (Sudo violations)                    |
|            │                                                                            |
|            ▼ (Threat Verified)                                                          |
|   [ SOAR Containment ] ──> 32-Bit CIDR Whitelist Immunity Check                        |
|   bin/containment.sh       ├── Driver: iptables / ufw (with mock fallback)              |
|                            ├── Atomic DROP Rule Injection (SENTINEL_IN chain)           |
|                            └── State Persistence in SQLite WAL & JSON Cache             |
|            │                                                                            |
|            ├───> [ Forensic Dossier Generator ] ──> data/incidents/*.md & *.json        |
|            ├───> [ Out-of-Band Dispatcher ]     ──> Slack Block Kit / Discord Embeds    |
|            └───> [ Database Layer ]             ──> server/db/sentinel.db (SQLite WAL)  |
|                                                              │                          |
|   [ FastAPI & SSE Gateway ] <────────────────────────────────┘                          |
|   server/main.py (Port 8000)                                                            |
|   ├── Dual-Track Auth: JWT Bearer + SHA-256 API Key                                     |
|   ├── Server-Sent Events (SSE): /api/v1/stream/logs & /alerts                           |
|   └── Full REST CRUD: Incidents, Containment, Rules, Whitelist                         |
|            │                                                                            |
|            ▼                                                                            |
|   [ Tactical SOC Web Console ]                                                          |
|   static/index.html (Obsidian & Glass, JetBrains Mono, Zero NPM build step)             |
|   ├── Real-Time Telemetry Cards (MTTR, Active Bans, Event Velocity)                     |
|   ├── Live Streaming Terminal with Pause/Resume & Search Filter                         |
|   ├── Incident Triage Matrix & Forensic Evidence Drawer                                 |
|   └── One-Click Quarantine / Release Modal (Ctrl+B Shortcut)                            |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Key Capabilities & Technical Specifications

| Domain | Capability | Implementation Details |
| :--- | :--- | :--- |
| **Ingestion** | Zero-Loss Log Streaming | POSIX `tail -F` ingestion pipeline handling log rotations and truncation without socket disconnection. |
| **Detection** | Sliding-Window Correlator | Sub-second stateful detection using memory-efficient bucket aggregations. Configurable sliding windows (default 60s-120s). |
| **Containment** | Kernel Netfilter SOAR | Dedicated `SENTINEL_IN` iptables chain. Automatic driver resolution (`iptables`, `ufw`, or deterministic `mock` for non-root test environments). |
| **Safety** | 32-Bit CIDR Bitmask Whitelist | Integer bitmask comparison protecting loopbacks (`127.0.0.0/8`), RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and custom security proxies from accidental lockouts. |
| **Forensics** | Automated Incident Dossiers | Instant generation of markdown (`.md`) and machine-readable (`.json`) forensic briefs with full timeline evidence. |
| **Dispatch** | Out-of-Band Notifier | Slack Block Kit and Discord Rich Embeds with local spool file queuing (`alert_spool.log`) for network partition resiliency. |
| **Storage** | SQLite WAL Persistence | Normalized schema with foreign key cascades, WAL mode (`PRAGMA journal_mode=WAL`), and thread-safe pool. |
| **API** | High-Throughput REST & SSE | FastAPI asynchronous endpoints, dual-track authentication (JWT Bearer with `jti` replay protection + SHA-256 API Key), and SSE log streaming. |
| **Console** | Tactical SOC Dashboard | Obsidian dark theme, Cybernetic Glass UI, zero-dependency vanilla ES6 + CSS tokens, real-time metrics, and instant triage drawer. |

---

## 3. Directory Layout

```
SOC Automation/
├── bin/
│   ├── common.sh           # Core Bash library, CIDR arithmetic, logging, driver probe
│   ├── ingestor.sh         # Log stream pipeline, normalizer, and FIFO consumer
│   ├── detector.sh         # Sliding-window correlation engine for threat rules
│   ├── containment.sh      # SOAR netfilter engine, ban/unban, state cache
│   ├── timeline.sh         # Forensic dossier (.md & .json) generator
│   ├── notifier.sh         # Slack/Discord webhook dispatcher and offline spooler
│   ├── db.sh               # CLI SQLite database interface bridge
│   └── sentinel.sh         # Master service CLI manager
├── config/
│   ├── sentinel.conf       # Master daemon configuration, thresholds, drivers
│   └── whitelist.conf      # CIDR blocks and IP addresses immune from containment
├── server/
│   ├── auth/               # JWT token manager, password hashing, RBAC middleware
│   ├── db/                 # SQLite connection pool, schema.sql, initialization script
│   ├── models/             # Pydantic validation models and API response contracts
│   ├── routes/             # REST endpoints (auth, incidents, containment, rules, stream)
│   └── main.py             # FastAPI master application with SSE & static mounting
├── static/
│   ├── css/style.css       # Obsidian & Glass SOC theme, responsive layout tokens
│   ├── js/app.js           # Single-page app controller, SSE consumer, modal bindings
│   └── index.html          # Cybernetic tactical SOC console interface
├── deploy/
│   ├── sentinel-engine.service   # Systemd unit for Bash daemon
│   ├── sentinel-api.service      # Systemd unit for FastAPI management server
│   ├── install.sh                # Production setup & sudoers configurator
│   └── uninstall.sh              # Clean removal and firewall teardown
├── tests/
│   ├── test_phase1.sh      # Core Bash ingestion & containment test suite (28 specs)
│   ├── test_phase2.sh      # Database schema, state & notifier test suite (17 specs)
│   ├── test_phase3.sh      # FastAPI, JWT, RBAC & SSE API test suite (12 specs)
│   ├── test_phase4.sh      # Simulator & UI regression test suite
│   ├── test_database.py    # Python SQLite WAL concurrency & schema tests
│   ├── test_api.py         # Pytest API integration test suite
│   └── simulate_attack.sh  # Interactive synthetic attack & red-team drill lab
├── Dockerfile              # Hardened container image with NET_ADMIN capability
├── docker-compose.yml      # Multi-container orchestration definition
└── requirements.txt        # Python production dependencies
```

---

## 4. Quickstart Guide

### Option A: Local Development & Verification

1. **Clone and Navigate:**
   ```bash
   git clone https://github.com/your-org/sentinelbash.git
   cd sentinelbash
   ```

2. **Set Up Python Environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Initialize the SQLite Database:**
   ```bash
   python server/db/init_db.py
   ```

4. **Start the API & Web Console:**
   ```bash
   uvicorn server.main:app --reload --port 8000
   ```
   Open your browser to **`http://localhost:8000`** (or access Swagger docs at `http://localhost:8000/docs`).  
   Default Administrator credentials:
   - **Username:** `admin`
   - **Password:** `AdminSentinel2026!`

5. **Start the Bash Engine (in a separate terminal):**
   ```bash
   bash bin/sentinel.sh start
   ```

---

### Option B: Docker Compose Deployment

Run SentinelBash with kernel netfilter access via `CAP_NET_ADMIN`:

```bash
docker-compose up --build -d
```
The console will be reachable on `http://localhost:8000`.

---

### Option C: Production Linux Host Installation (Systemd)

Execute the production installer with administrative privileges:

```bash
sudo bash deploy/install.sh
```

Enable and start the system services:
```bash
sudo systemctl enable --now sentinel-engine
sudo systemctl enable --now sentinel-api
```

---

## 5. Master CLI Management (`bin/sentinel.sh`)

SentinelBash provides a centralized POSIX CLI for all service operations:

```bash
# Check daemon and firewall health
bash bin/sentinel.sh status

# Start, stop, or restart the detection pipeline
bash bin/sentinel.sh start
bash bin/sentinel.sh stop
bash bin/sentinel.sh restart

# Inspect active Netfilter quarantine bans
bash bin/sentinel.sh bans

# Manually isolate a suspicious IP address
bash bin/sentinel.sh block 198.51.100.42 "Manual SOC Analyst Quarantine"

# Unban an IP address
bash bin/sentinel.sh unban 198.51.100.42

# Emergency firewall flush (wipes SENTINEL_IN chain)
bash bin/sentinel.sh flush

# Inspect detection rules and configured thresholds
bash bin/sentinel.sh rules

# Display protected CIDR whitelist
bash bin/sentinel.sh whitelist

# Tail live engine logs
bash bin/sentinel.sh logs -n 50
```

---

## 6. Synthetic Attack Laboratory (`tests/simulate_attack.sh`)

SentinelBash includes a built-in red-team drill laboratory to simulate attacks and measure sub-second containment latency:

```bash
# Run the complete automated drill scenario suite
bash tests/simulate_attack.sh --all

# Or execute specific tactical scenarios:
bash tests/simulate_attack.sh --ssh        # SSH Brute Force velocity attack
bash tests/simulate_attack.sh --web        # Path traversal & .env/.git probes
bash tests/simulate_attack.sh --sudo       # Privilege escalation attempts
bash tests/simulate_attack.sh --whitelist  # Whitelist immunity protection test
```

Sample output:
```
[SECURITY] Simulating Scenario A: SSH Brute Force Velocity (6 attempts from 198.51.100.111)...
[CONTAIN] Driver: mock | Action: BAN | Target: 198.51.100.111 | Rule: SSH_BRUTE_FORCE
[CONTAIN] IP 198.51.100.111 isolated in firewall. State cached.
[NOTIFIER] Alert dispatched to Slack/Discord spool.
[FORENSIC] Incident INC-20260925-0001 dossier generated.
[SUCCESS] SSH Attack successfully detected and quarantined in 0s!
```

---

## 7. Security Architecture & Threat Model

1. **Immunity Guarantee (CIDR Bitmask Engine):**
   Prior to executing any kernel `DROP` directive, SentinelBash parses `config/whitelist.conf` into 32-bit unsigned integers. Every target IP is evaluated against bitmask ranges using bitwise shifts. Localhost (`127.0.0.0/8`), private gateways (`10.0.0.0/8`, `192.168.0.0/16`), and configured DNS servers are mathematically immune to lockout.

2. **DDoS & Race Condition Defense:**
   The containment engine maintains an in-memory and disk-backed state index (`data/run/active_bans.state`). Duplicate triggers for an already-quarantined IP are suppressed in $O(1)$ time, preventing rule table bloat in Netfilter.

3. **Cryptographic Token Replay Protection:**
   The FastAPI management gateway enforces JWT tokens signed with HMAC-SHA256. Every generated access token embeds a unique 128-bit cryptographic nonce (`jti`). Revoked or expired nonces are rejected.

4. **Least-Privilege Isolation:**
   When installed as a system service, the web API runs under an unprivileged `sentinel` service account, invoking firewall actions strictly via a scoped sudoers definition (`/etc/sudoers.d/sentinelbash`).

---

## 8. Verification & Test Suite

The test suite validates end-to-end functionality across all components:

```bash
# Phase 1: Core Bash Ingestion, Detection & Containment (28 tests)
bash tests/test_phase1.sh

# Phase 2: SQLite WAL Database, Concurrency & Notifier (17 tests)
bash tests/test_phase2.sh

# Phase 3: FastAPI REST Endpoints, Auth & SSE Streaming (12 tests)
bash tests/test_phase3.sh

# Phase 4: Full Deployment, Attack Simulator & UI Validation
bash tests/test_phase4.sh

# Python Pytest Unit & Integration Tests
pytest tests/test_database.py tests/test_api.py -v
```

**Total Test Coverage:** 70+ automated assertions across POSIX Bash and Python.

---

## 9. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
