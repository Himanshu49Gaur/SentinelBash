# Step-by-Step Implementation Roadmap & Engineering Plan

**Project Name:** SentinelBash — SOC Automation & Incident Response Platform  
**Document Version:** 1.0.0  
**Status:** Ready for Execution  
**Lead Roles:** Senior Full-Stack Engineer & Technical Project Manager  
**Companion Documents:**  
- [PRD.md](file:///d:/SOC%20Automation/PRD.md)  
- [TRD.md](file:///d:/SOC%20Automation/TRD.md)  
- [APP_FLOW.md](file:///d:/SOC%20Automation/APP_FLOW.md)  
- [UI_UX_DESIGN_BRIEF.md](file:///d:/SOC%20Automation/UI_UX_DESIGN_BRIEF.md)  
- [BACKEND_SCHEMA.md](file:///d:/SOC%20Automation/BACKEND_SCHEMA.md)  

---

## 1. Project Overview & Execution Strategy

The SentinelBash implementation is organized into **9 sequential, test-driven phases**. The roadmap follows an "engine-first, glass-pane-second" methodology: first establishing the core Bash ingestion, netfilter containment, and SQLite state engine, followed by the asynchronous management API, and culminating in the analyst web console and attack simulation laboratory.

```mermaid
gantt
    title SentinelBash End-to-End Implementation Schedule
    dateFormat  X
    axisFormat Phase %s

    section Engine & Storage
    Phase 1: Project Setup & Toolchain       :active, p1, 0, 1
    Phase 2: Database Schema & Migrations    :p2, 1, 2
    Phase 3: Authentication & Security       :p3, 2, 3
    Phase 4: Core Bash SOC Automation Engine :p4, 3, 5

    section API & UI
    Phase 5: Backend API & SSE Gateway       :p5, 5, 7
    Phase 6: Tactical Analyst Web Console    :p6, 7, 9
    Phase 7: Alerting Integrations & Spooler :p7, 9, 10

    section Quality & Delivery
    Phase 8: Attack Simulator & Test Suite   :p8, 10, 12
    Phase 9: Deployment & Final Polish       :p9, 12, 13
```

---

## 2. Phase-by-Phase Detailed Implementation Plan

---

### Phase 1: Environment & Project Setup

#### Objectives & Tasks
1. Initialize repository directory hierarchy according to [TRD.md](file:///d:/SOC%20Automation/TRD.md).
2. Configure shell environment scripts with strict safety flags (`set -euo pipefail`).
3. Set up Python virtual environment and install lightweight API dependencies (`fastapi`, `uvicorn`, `pydantic`, `pyjwt`, `passlib[argon2]`).
4. Establish `.gitignore`, `.env.example`, and configuration templates (`sentinel.conf`, `whitelist.conf`).

#### Key Deliverables
- [x] Canonical directory tree:
  ```text
  bin/          # Core Bash daemons
  config/       # Configuration templates
  server/       # FastAPI gateway & SSE server
  static/       # Web console assets (HTML, CSS, JS)
  tests/        # Simulation and unit tests
  deploy/       # Systemd units and installer
  ```
- [x] `config/sentinel.conf` with default threshold parameters.
- [x] `config/whitelist.conf` with default loopback and private CIDRs.
- [x] `requirements.txt` locking lightweight Python dependencies.

---

### Phase 2: Database Schema, Migrations & State Store

#### Objectives & Tasks
1. Implement the SQLite schema defined in [BACKEND_SCHEMA.md](file:///d:/SOC%20Automation/BACKEND_SCHEMA.md).
2. Write database initialization script (`server/db/init_db.py` / `init_db.sh`) enabling WAL mode and indexing.
3. Implement lightweight Data Access Object (DAO) layer for atomic reads/writes from both Bash and Python.
4. Seed default detection rules (`RULE_SSH_BRUTE_FORCE`, `RULE_WEB_PROBE`, `RULE_SUDO_ABUSE`) and default admin user account.

#### Key Deliverables
- [x] `server/db/schema.sql` containing all 9 tables and compound indexes.
- [x] `server/db/database.py` with thread-safe SQLite connection pool and WAL mode setup.
- [x] Seed migration script producing initialized `/var/lib/sentinel/sentinel.db`.
- [x] Schema integrity verification unit test (`tests/test_database.py`).

---

### Phase 3: Authentication, Session & Access Control

#### Objectives & Tasks
1. Implement password hashing using Argon2id with automatic salt generation.
2. Build JWT token generation and validation middleware with HMAC-SHA256 signing.
3. Implement API Key verification (`snt_live_...`) with SHA-256 hash lookups.
4. Implement Role-Based Access Control (RBAC) middleware verifying permissions (`ADMIN`, `ANALYST`, `AUDITOR`).

#### Key Deliverables
- [x] `server/auth/security.py` (Password hashing, JWT encode/decode, API key verification).
- [x] `server/auth/dependencies.py` (FastAPI dependency injection for authenticated roles).
- [x] `/api/v1/auth/token` and `/api/v1/auth/refresh` endpoints.
- [x] Automated auth test suite testing token expiration, invalid signatures, and role boundaries.

---

### Phase 4: Core Bash SOC Automation Engine

#### Objectives & Tasks
1. **`bin/ingestor.sh`**: Stream log listener with `tail -n 0 -F` support, parsing `/var/log/auth.log` and emitting normalized records into `/run/sentinel/log.fifo`.
2. **`bin/detector.sh`**: Ingestion consumer utilizing sliding-window timestamp arrays to calculate failure frequency against defined thresholds.
3. **`bin/containment.sh`**: Netfilter engine verifying whitelist immunity before injecting tagged `iptables` drop rules (`-m comment --comment "SENTINEL:<INC_ID>"`).
4. **`bin/timeline.sh`**: Forensic dossier compiler authoring Markdown investigation files in `/var/log/sentinel/incidents/`.
5. **`bin/sentinel.sh`**: Master CLI orchestrator managing sub-daemon lifecycles, PID files, and signal handling (`SIGTERM`, `SIGHUP`).

#### Key Deliverables
- [x] `bin/ingestor.sh` (Resilient streaming with logrotate survival).
- [x] `bin/detector.sh` (Sliding window regex evaluator).
- [x] `bin/containment.sh` (Safe `iptables`/`ufw` operator with duplicate-rule suppression).
- [x] `bin/timeline.sh` (Automated forensic report generator).
- [x] `bin/sentinel.sh` (CLI manager: `start`, `stop`, `status`, `unban <IP>`).

---

### Phase 5: Backend REST API & Real-Time SSE Gateway

#### Objectives & Tasks
1. Implement REST endpoints per [TRD.md](file:///d:/SOC%20Automation/TRD.md):
   - `GET /api/v1/health`
   - `GET /api/v1/incidents` (with pagination, search, status filter)
   - `GET /api/v1/incidents/{id}`
   - `POST /api/v1/containment/block`
   - `POST /api/v1/containment/unban`
   - `POST /api/v1/containment/flush`
2. Implement Server-Sent Events (SSE) streaming gateway (`GET /api/v1/stream/logs` and `GET /api/v1/stream/alerts`) tailing the FIFO queue asynchronously.
3. Implement audit logging interceptor recording all administrative actions to `audit_logs`.

#### Key Deliverables
- [x] `server/routes/incidents.py`
- [x] `server/routes/containment.py`
- [x] `server/routes/stream.py` (SSE asynchronous streaming)
- [x] `server/main.py` mounting routes with CORS and security headers.
- [x] Postman / OpenAPI (`/docs`) swagger interactive schema.

---

### Phase 6: Tactical Analyst Web Console (UI)

#### Objectives & Tasks
1. Build single-page responsive UI matching [UI_UX_DESIGN_BRIEF.md](file:///d:/SOC%20Automation/UI_UX_DESIGN_BRIEF.md):
   - Tactical dark-mode theme (`#0B0F17` base, `#111827` cards, cyan cyber accents).
   - Google Fonts typography (`Outfit`, `Inter`, `JetBrains Mono`).
2. Build layout shell (Persistent sidebar, sticky header, live connection indicator, toast stack).
3. Implement all 7 core views from [APP_FLOW.md](file:///d:/SOC%20Automation/APP_FLOW.md):
   - **Operations Dashboard**: Metric cards, active ban list, attack vector chart.
   - **Real-Time Log Triage**: Monospace terminal stream with pause/resume buffer.
   - **Incidents Hub**: Filterable table with CSV export.
   - **Incident Detail Drawer**: Vertical forensic timeline with Markdown report preview.
   - **Containment Manager**: Active firewall table with one-click unban.
   - **Rules Config**: Form to tune thresholds and whitelist.
   - **Emergency Quarantine Modal (`Ctrl+B`)**.

#### Key Deliverables
- [x] `static/index.html` (Semantic single-page app structure with unique element IDs).
- [x] `static/css/style.css` (Tailwind CDN / custom CSS design tokens & animations).
- [x] `static/js/app.js` (Modular UI controller, SSE listener, keyboard shortcuts, optimistic state updates).
- [x] Cross-browser and mobile responsive verified layout.

---

### Phase 7: Alerting Integrations & Notification Spooler

#### Objectives & Tasks
1. Implement `bin/notifier.sh` and Python notification dispatcher.
2. Build Slack Block Kit webhook adapter delivering color-coded incident cards.
3. Build offline alert spooler (`/var/log/sentinel/alert_spool.log`) with retry daemon for network recovery.
4. Support optional secondary channels (Discord Webhook, Email via `mailx`).

#### Key Deliverables
- [x] `bin/notifier.sh` (cURL-based webhook dispatcher with exponential backoff).
- [x] Formatted Slack Block Kit payload template matching severity tiers.
- [x] Notification delivery audit logging in `notifications_log` table.

---

### Phase 8: Attack Simulator & Automated Test Suite

#### Objectives & Tasks
1. Develop `tests/simulate_attack.sh` synthesizing:
   - Scenario A: SSH Brute Force (6 failed attempts in 4s).
   - Scenario B: Web Exploit Sweep (Path traversal probes).
   - Scenario C: Whitelist Bypass verification (simulated failed auth from `127.0.0.1`).
2. Implement automated end-to-end test verifying:
   - Event detected in $< 2.0\text{s}$.
   - Kernel netfilter drop rule created.
   - SQLite incident record marked `CONTAINED`.
   - Markdown report generated.
   - Slack payload formatted correctly.
3. Static code analysis: ShellCheck on all `.sh` scripts; Ruff and Mypy on Python backend.

#### Key Deliverables
- [x] `tests/simulate_attack.sh` (Interactive CLI demo and automated test).
- [x] `tests/run_all_tests.sh` (One-shot CI test runner).
- [x] Mock log generator for offline development on non-Linux hosts.

---

### Phase 9: Deployment, Production Hardening & Final Polish

#### Objectives & Tasks
1. Author systemd service units (`sentinel-engine.service` and `sentinel-api.service`).
2. Build idempotent one-line installer script `install.sh`:
   - System user `sentinel` creation.
   - Sudoers rule creation for targeted `iptables` execution (`/etc/sudoers.d/sentinel`).
   - File permission hardening (`chmod 600` on secrets and configs).
3. Docker containerization (`Dockerfile` and `docker-compose.yml`) with `CAP_NET_ADMIN` capabilities for testing on any workstation.
4. Final project documentation: Architecture diagram, demo GIF guide, interview talking points.

#### Key Deliverables
- [x] `deploy/sentinel-engine.service` & `deploy/sentinel-api.service`.
- [x] `deploy/install.sh` & `deploy/uninstall.sh`.
- [x] `Dockerfile` & `docker-compose.yml`.
- [x] Comprehensive `README.md` with installation commands and interview portfolio talking points.

---

## 3. Milestones & Definition of Done (DoD)

| Milestone | Target Completion | Acceptance Criteria |
| :--- | :--- | :--- |
| **M1: Engine & Storage Core** | Phases 1 – 4 | Simulated SSH brute force automatically creates `iptables` drop rule and writes Markdown dossier within 2 seconds. |
| **M2: API & Gateway** | Phase 5 | REST API serves incident records and streams raw logs via SSE to `curl` client. |
| **M3: Functional Web Console** | Phase 6 | Web UI connects via SSE, visualizes live attacks, and allows one-click unban of quarantined IPs. |
| **M4: Production Ready MVP** | Phases 7 – 9 | Passes all automated tests, installs cleanly via `install.sh`, and handles network dropouts gracefully. |

