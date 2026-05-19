# 🔐 SecureCloud Enterprise SOC Platform v4.0

**The most complete AI-powered cybersecurity simulation platform.**
No AWS credentials required. Everything is simulated.

---

## ▶️ Quick Start

```bash
# 1. Install all dependencies (one command)
npm run install:all

# 2. Start everything
npm run dev
```

**→ Open http://localhost:5173**

---

## 🔑 Demo Accounts

| Role   | Username | Password        | Access                     |
|--------|----------|-----------------|----------------------------|
| Viewer | viewer   | Viewer123!      | Read-only, all dashboards  |
| Admin  | admin    | AdminSecure123! | Full access + analysis     |

Click credential rows on the login page to auto-fill.

---

## 🗺 Threat Map — OpenStreetMap (Zero Config)

The Threat Map uses **OpenStreetMap + Leaflet** — completely free, no API key, no billing, no account.

Features included out of the box:
- 🌍 Full interactive world map (dark/light themes via CartoDB/OSM tiles)
- ⚡ Animated attack arcs (AntPath) from origin to cloud target
- 📍 Pulsing severity-colored markers (auto-expire 8–15 seconds)
- 🔵 Marker clustering for dense attack regions
- 🔍 Zoom, pan, reset view controls
- 📊 Live stats overlay + severity legend

No configuration needed — just `npm run dev`.

---

## 🏗 What's New in v4.0

### 1. Fixed Sidebar Architecture (Persistent Layout)
- Sidebar **never unmounts** — uses React Router `<Outlet />` pattern
- Icons-only collapsed mode with hover tooltips
- Mobile slide-in drawer with backdrop blur
- Smooth width transition, active link highlighting
- Badge counter for active threats

### 2. Elite Threat Map
- **Google Maps integration** with custom dark/light styling
- **Animated attack arcs** from origin to your cloud (cinematic!)
- Pulsing markers with auto-expiry (10-15s)
- Click-to-inspect detail panel
- Real-time counter overlay
- **Professional SVG fallback** if no API key

### 3. AI Copilot Elite Mode
- **Domain restriction** — refuses non-cybersecurity questions
- **Typing animation** — character-by-character streaming effect
- Prompt chips organized by category
- Click any event to auto-trigger analysis
- Markdown-formatted responses with bold highlights

### 4. Animated Dashboard
- Radial **risk score gauge** with needle animation
- **Animated metric counters** (smooth number transitions)
- Notification bell with dropdown history
- Alert sound system (toggleable)

### 5. Profile & Notifications
- **Notification bell** with unread badge
- Alert sound effects (mutable)
- Edit display name inline
- Smooth dropdown animations

### 6. Complete Light/Dark Mode
- Charts adapt instantly
- Google Maps switches style
- All components themed
- Persisted in localStorage

### 7. Mobile Responsive
- Sidebar collapses automatically at <1024px
- Hamburger menu on mobile
- Stacked card layouts on small screens
- No overflow or cut-off UI

---

## 📡 Architecture

```
securecloud-v4/
├── backend/                 Node.js + Express + WebSocket
│   ├── server.js            HTTP server + JWT auth middleware
│   ├── routes/auth.js       Login endpoint (POST /api/auth/login)
│   ├── routes/api.js        Protected API endpoints (15 routes)
│   ├── websocket/wsServer.js  Live event streaming
│   ├── simulation/          Event generator + behavior models
│   ├── ai/                  Threat detector + AI copilot responses
│   └── services/            Zero Trust + IAM analyzer
│
└── frontend/                React + Vite + Tailwind + Chart.js
    ├── src/
    │   ├── App.jsx           Nested routing — sidebar NEVER unmounts
    │   ├── context/          Auth + Theme + Notifications
    │   ├── hooks/            useWebSocket (auto-reconnect)
    │   ├── components/       Sidebar, Topbar, EventFeed, UI primitives
    │   └── pages/            8 dashboard pages
    └── .env                  Optional Google Maps API key
```

---

## 🔗 API Endpoints

### Public
```
POST /api/auth/login    → { token, user }
POST /api/auth/verify   → { valid, user }
GET  /health
```

### Protected (Bearer token required)
```
GET  /api/dashboard/stats
GET  /api/events?count=N
GET  /api/zero-trust/snapshot
GET  /api/iam/analyze
GET  /api/behavior/users
GET  /api/behavior/attack-windows
GET  /api/intelligence/threat-types
GET  /api/intelligence/attack-prediction
POST /api/ai/chat
POST /api/ai/analyze
```

### WebSocket `ws://localhost:4000/ws`
```
SECURITY_EVENT  → every 2-5 seconds
THREAT_WAVE     → coordinated attack burst every 20-50s
STATS_UPDATE    → live counter updates
HEARTBEAT       → 10s keepalive
```

---

## 🧠 Simulation Formulas

```
Risk Score    = (Behavior × 0.4) + (Network × 0.3) + (Access × 0.3)
Zero Trust    = Identity × Device × Behavior × Context
Attack Prob   = Weighted sigmoid of time-of-day risk windows
Anomaly Score = Deviation from user baseline behavior model
```

---

## 💼 Resume Bullets

- Built enterprise cybersecurity SOC simulation platform with React + Node.js + WebSocket
- Implemented JWT authentication with RBAC (admin/viewer roles) and auto-logout on token expiry
- Integrated Google Maps JavaScript API with custom dark-theme styling and animated SVG fallback
- Engineered real-time threat visualization with animated attack arcs, pulsing geo-markers, and auto-expiry
- Developed AI Security Copilot with domain restriction, streaming typing effect, and MITRE ATT&CK analysis
- Built persistent sidebar layout using React Router nested routes (Outlet pattern)
- Implemented Zero Trust scoring engine: Identity × Device × Behavior × Context trust formula
- Added notification system with bell dropdown, sound alerts, and unread badge management
