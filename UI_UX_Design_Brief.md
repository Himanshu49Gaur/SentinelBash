# UI/UX Design Brief & Design System Specification

**Project Name:** SentinelBash — SOC Automation & Incident Response Console  
**Document Version:** 1.0.0  
**Status:** Approved for Implementation & UI Generation  
**Role:** Senior Principal UI/UX Designer & Design Systems Lead  
**Companion Documents:** [PRD.md](file:///d:/SOC%20Automation/PRD.md) | [TRD.md](file:///d:/SOC%20Automation/TRD.md) | [APP_FLOW.md](file:///d:/SOC%20Automation/APP_FLOW.md)  

---

## 1. Design Style & Visual Philosophy

### 1.1 Aesthetic Theme: "Tactical Obsidian & Cybernetic Glass"
The visual identity of SentinelBash merges the high-performance ergonomics of a modern command-and-control defense system (e.g., Cloudflare Zero Trust, Datadog Cloud SIEM, CrowdStrike Falcon) with the hyper-polished dark minimalism of Linear and Vercel.

- **Dark-Adapted Ergonomics:** Purpose-built for low-light SOC environments. Avoids harsh stark blacks (`#000000`) in favor of rich, multi-layered obsidian and deep navy-gray slate backgrounds (`#0B0F17`, `#111827`) that reduce eye fatigue over 12-hour shifts.
- **Glassmorphism with Discipline:** Subtle semi-transparent surfaces (`backdrop-blur-md`, `bg-opacity-80`) with delicate 1px border highlights (`rgba(255, 255, 255, 0.08)`). No gratuitous neon gradients or cartoonish cyberpunk tropes; all visual accents serve information hierarchy.
- **High-Density Data Display:** High information density without visual clutter. Tightly packed metric cards, monospaced IP addresses, and micro-badges allow analysts to evaluate threat state at a glance.
- **Micro-Animations for Kinetic Feedback:** Pulsing status beacons, smooth row-fade containment transitions, and dynamic terminal streaming bars keep the interface feeling responsive and alive.

---

## 2. Comprehensive Color Palette & Design Tokens

```
Canvas / Backgrounds:
  Canvas (Base):        #0B0F17  (Deep Obsidian Void)
  Surface Level 1:      #111827  (Charcoal Slate - Cards & Panels)
  Surface Level 2:      #1F2937  (Elevated Slate - Hover states, Modals)
  Surface Level 3:      #374151  (Input Fields, Borders, Dividers)

Cyber Accents:
  Cyan Primary:         #06B6D4  (Glow / Active Navigation / Charts)
  Cyan Hover / Bright:  #22D3EE  (Interactive highlights)
  Cyan Glow Shadow:     rgba(6, 182, 212, 0.18)

Threat & Severity Palette:
  CRITICAL / DROP:      #EF4444  (Crimson Red - Blocked IPs, Attack Thresholds)
  HIGH / ALERT:         #F59E0B  (Amber Orange - Directory Traversal, Sudo Abuse)
  MEDIUM / SYSTEM:      #3B82F6  (Electric Blue - Normal Events, Service Reloads)
  LOW / SAFE:           #10B981  (Emerald Green - Whitelisted, Clean Health, Unbanned)

Typography / Text Tokens:
  Text Primary:         #F9FAFB  (98% White - Headings, active values)
  Text Secondary:       #9CA3AF  (Cool Gray - Labels, metadata, timestamps)
  Text Muted:           #6B7280  (Dim Slate - Placeholders, disabled states)
  Text Monospace Code:  #38BDF8  (Sky Cyan - IPs, commands, regexes)
```

### 2.1 CSS Custom Properties Token Sheet
```css
:root {
  /* Surface Layers */
  --bg-canvas: #0B0F17;
  --bg-surface-1: #111827;
  --bg-surface-2: #1F2937;
  --bg-surface-3: #374151;
  --border-subtle: rgba(255, 255, 255, 0.08);
  --border-focus: #06B6D4;

  /* Accent Tokens */
  --accent-cyan: #06B6D4;
  --accent-cyan-hover: #22D3EE;
  --accent-glow: 0 0 15px rgba(6, 182, 212, 0.25);

  /* Status Tokens */
  --status-critical: #EF4444;
  --status-critical-bg: rgba(239, 68, 68, 0.12);
  --status-high: #F59E0B;
  --status-high-bg: rgba(245, 158, 11, 0.12);
  --status-medium: #3B82F6;
  --status-medium-bg: rgba(59, 130, 246, 0.12);
  --status-safe: #10B981;
  --status-safe-bg: rgba(16, 185, 129, 0.12);

  /* Typography */
  --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-display: 'Outfit', sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
}
```

---

## 3. Typography Hierarchy & Rules

| Role | Font Family | Size | Weight | Tracking / Line Height | Sample Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Display / Brand** | `Outfit` | `24px` | Bold (`700`) | `-0.02em` / `1.2` | Console Header: **SENTINEL // BASH** |
| **Heading 1 (Page)** | `Outfit` | `20px` | SemiBold (`600`) | `-0.01em` / `1.3` | Page Titles: **Incident Dossier: INC-8F32** |
| **Heading 2 (Card)** | `Inter` | `14px` | SemiBold (`600`) | `+0.02em` (Uppercase) | Card Titles: **ACTIVE QUARANTINE RULES** |
| **Metric Hero** | `JetBrains Mono` | `28px` | Bold (`700`) | `-0.03em` / `1.0` | KPI Values: **1.4s** (MTTD), **8** (Active Bans) |
| **Body (Default)** | `Inter` | `14px` | Regular (`400`) | `normal` / `1.5` | Descriptions, incident notes, modal text |
| **Body Small / Meta**| `Inter` | `12px` | Medium (`500`) | `+0.01em` / `1.4` | Timestamps: `11:20:12 UTC (3m ago)` |
| **Monospace Telemetry**| `JetBrains Mono`| `13px` | Regular/Medium (`500`)| `normal` / `1.4` | IP Addresses: `203.0.113.45`, Log Lines |
| **Micro Badge** | `Inter` | `10px` | Bold (`700`) | `+0.05em` (Uppercase) | Status Pills: `[CONTAINED]`, `[WHITELIST]` |

---

## 4. Layout Direction & Spatial Grid

### 4.1 Master 12-Column Grid & Density Layout
- **Max Canvas Width:** `1600px` centered with fluid `padding-x: 24px`.
- **Vertical Rhythm & Gaps:** Baseline 8px grid system (`gap-4 = 16px`, `gap-6 = 24px`).
- **Persistent Left Sidebar:** Fixed `260px` width on desktop (`z-index: 40`). Collapses to icon-only (`72px`) on tablet (`1024px`), and converts to a slide-over off-canvas drawer on mobile (`< 768px`).
- **Sticky Top Bar:** Fixed `64px` height with backdrop blur (`backdrop-blur-md bg-opacity-80`). Houses breadcrumbs, search shortcut, and live engine status pill.

```text
+----------------------------------------------------------------------------------------------------+
|  SIDEBAR (260px)   |  TOP HEADER (Height: 64px, Sticky, Glassmorphism)                              |
|                    |  Breadcrumbs / Global Search [Ctrl+K] / [+ Quarantine IP] / [Live Stream ●]    |
|  [Shield] SENTINEL |-------------------------------------------------------------------------------|
|  ● Engine: Active  |  MAIN CONTENT VIEWPORT (Max-width: 1600px, Padding: 24px)                     |
|                    |  +-------------------------------------------------------------------------+  |
|  - Dashboard       |  |  4-Col KPI Metrics Grid (MTTD | Active Bans | 24h Threats | Health)     |  |
|  - Real-Time Logs  |  +-------------------------------------------------------------------------+  |
|  - Incidents       |  |  Main Split View (65% / 35%):                                           |  |
|  - Containment     |  |  [ Real-Time Ingestion Stream (SSE) ]  | [ Active Netfilter Block List] |  |
|  - Rules Config    |  |  [ High-density interactive terminal]  | [ Compact table + Quick Unban] |  |
|  - Lab Simulator   |  +-------------------------------------------------------------------------+  |
|                    |-------------------------------------------------------------------------------|
|  Operator Profile  |  STATUS FOOTER (Height: 32px)                                                 |
|  [Logout]          |  Linux Netfilter: OK | SQLite WAL: Active | Ingestion: 18.4 lines/sec         |
+----------------------------------------------------------------------------------------------------+
```

---

## 5. Component Design Specifications

### 5.1 Metric / KPI Cards
- **Container:** `background: #111827`, `border: 1px solid rgba(255, 255, 255, 0.08)`, `border-radius: 12px`, `padding: 20px`.
- **Hover State:** Border transitions to `rgba(6, 182, 212, 0.4)` with subtle glow box-shadow `0 4px 20px rgba(6, 182, 212, 0.08)`.
- **Top Row:** Title in uppercase `12px Cool Gray` with a themed SVG icon in a round translucent chip (`bg-opacity-10`).
- **Value:** `28px JetBrains Mono` in pure white `#F9FAFB`.
- **Delta Subtitle:** `12px` font with directional indicator (e.g. `▲ +12% from yesterday` in green/red).

### 5.2 Status Pills & Badges
Every badge uses a semi-transparent tinted background, high-contrast colored text, a 1px border, and an animated pulsing indicator dot:
- **`[ 🔴 CONTAINED ]`:** `bg-red-500/10 text-red-400 border-red-500/30` with `animate-pulse` crimson dot.
- **`[ 🟡 SUSPICIOUS ]`:** `bg-amber-500/10 text-amber-400 border-amber-500/30`.
- **`[ 🟢 SAFE / WHITELIST ]`:** `bg-emerald-500/10 text-emerald-400 border-emerald-500/30`.
- **`[ ⚪ RELEASED ]`:** `bg-gray-500/10 text-gray-400 border-gray-500/30`.

### 5.3 Buttons & Interactive Controls
- **Primary Cyber Button (`[+ Quarantine IP]`):**
  - Gradient background: `linear-gradient(135deg, #06B6D4 0%, #0284C7 100%)`.
  - Text: `#0B0F17` (Deep Obsidian for maximum legibility) or `#FFFFFF` bold.
  - Hover: Scales `1.02`, box shadow `0 0 16px rgba(6, 182, 212, 0.4)`.
  - Active: Scale `0.98`.
- **Danger Button (`[Release Ban / Unban]`):**
  - Dark surface with red outline: `bg-red-950/20 text-red-400 border border-red-500/40`.
  - Hover: `bg-red-600 text-white shadow-lg shadow-red-600/30`.
- **Secondary Ghost Button (`[Export CSV]`):**
  - `bg-transparent text-gray-300 border border-gray-700`.
  - Hover: `bg-gray-800 text-white border-gray-600`.

### 5.4 High-Performance Monospace Log Terminal Component
- **Container:** Pure `#070A0F` background with subtle inner shadow, simulating an authenticated console terminal.
- **Header:** Terminal controls (Mac-style red/yellow/green micro-dots on the left), Service selector tabs, and real-time ingestion rate counter (`14.2 lines/s`).
- **Typography:** `13px JetBrains Mono`, line height `1.6`.
- **Syntax Highlighting:**
  - Timestamps: `#6B7280` (Muted Gray)
  - Service tags (`[SSHD]`, `[NGINX]`): `#38BDF8` (Sky Cyan pill)
  - Malicious triggers (`Failed password`, `404 Directory Traversal`): `#F87171` (Crimson bold)
  - Target IP addresses: `#FCD34D` (Gold/Amber) with clickable underline that triggers the inspector drawer.

### 5.5 Forensic Chronology Timeline
- **Layout:** Vertical linked timeline with a glowing 2px central spine (`border-cyan-500/30`).
- **Nodes:** Circular icons positioned on the spine:
  - Incident Trigger: Red warning icon with ripple animation.
  - Netfilter Rule Application: Shield icon with emerald glow.
  - Slack Webhook Delivery: Chat bubble icon with purple glow.
- **Dossier Cards:** Attached to nodes with timestamp, actor attribution, raw event extract, and verification hashes.

---

## 6. Mobile Responsiveness & Breakpoint Architecture

SentinelBash is optimized for responsive mobile triage, enabling on-call SecOps engineers to review alerts and unban false positives directly from a phone or tablet.

| Breakpoint | Width Range | Layout Transformations |
| :--- | :--- | :--- |
| **Mobile (`sm`)** | `< 640px` | • Sidebar collapses completely into bottom navigation bar (Home, Logs, Incidents, Actions).<br>• Metric cards stack in a single column (1x4).<br>• Split views (Log Stream / Block list) convert into tabbed toggle views.<br>• Table cells truncate secondary metadata, showing only IP + Threat + Action button.<br>• Modals convert to bottom action sheets (`drawer-bottom`). |
| **Tablet (`md` / `lg`)**| `641px - 1024px`| • Sidebar collapses to slim 72px icon bar.<br>• Metric cards reflow to a 2x2 grid.<br>• Tables retain full columns with horizontal scrolling for log payloads. |
| **Desktop (`xl` / `2xl`)**| `> 1024px` | • Full 260px expanded sidebar.<br>• 4-column metric cards.<br>• 65% / 35% asymmetric split view for log streaming and containment tables. |

---

## 7. Core User Experience Principles

1. **Sub-Second Feedback Loop:** Security operators work under high stress. Every button click (such as manual block or unban) updates the UI optimistically within $< 50\text{ms}$ with a confirmation toast, synchronizing the backend in parallel.
2. **Fail-Safe by Default:** Destructive actions (such as flushing all firewall rules or unbanning an IP currently undergoing an attack) require explicit two-step confirmation or keyword entry (`"FLUSH"`).
3. **Information Density without Chaos:** Data tables utilize compact padding (`py-2.5 px-4`), clear zebra striping (`bg-white/[0.02]`), and sticky table headers, ensuring analysts never lose column orientation while scrolling through hundreds of entries.
4. **Context Preservation:** Clicking on an incident or log line never forces a full page reload; inspector drawers slide over smoothly, allowing the analyst to maintain visual orientation on the live feed.

---

## 8. Visual References & Aesthetic Benchmarks

| Benchmark Platform | Aesthetic Element Adopted for SentinelBash |
| :--- | :--- |
| **Datadog Security Monitoring** | Color-coded severity badge taxonomy (`CRITICAL`, `HIGH`, `INFO`) and high-density metric summary ribbons. |
| **Cloudflare Zero Trust / Radar** | Real-time packet/threat stream visualization and clean, minimalist dark surface layering. |
| **Linear App** | Ultra-refined keyboard-first navigation (`Ctrl+K`), micro-interactions, and 1px crisp borders. |
| **GitHub Actions Log Streamer** | Autoscrolling virtualized log console with search highlight and pause-on-scroll ergonomics. |

---

## 9. AI App Builder Implementation Directive

When building the HTML/CSS/JS frontend for SentinelBash:
1. **Never use generic browser defaults:** Use Google Fonts (`Outfit` for headings, `Inter` for UI, `JetBrains Mono` for telemetry).
2. **Never use solid black backgrounds:** Always use `#0B0F17` for the canvas and `#111827` for cards and panels.
3. **Incorporate the Cyan Cyber Accent:** Use `#06B6D4` for primary buttons, active link indicators, and glowing badges.
4. **Ensure full interactivity:** All tables must include functioning search filters, tabs must switch without reloading, and action buttons must display realistic loading spinners and confirmation toasts.

