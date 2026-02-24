# Nightfall Tsukuyomi v2.0

**Unified Security Platform** — Nightfall Scanner + OpenCTI + OpenBAS

> Reconnaissance, Threat Intelligence, and Breach & Attack Simulation in a single pane of glass.

---

## Architecture

| Engine | Role | Port | Technology |
|--------|------|------|------------|
| **Nightfall Scanner** | Active/Passive recon & vuln scanning | 8080 (backend), 80 (frontend) | Go, React |
| **OpenCTI** | Cyber Threat Intelligence (CTI) | 8081 | Node.js, GraphQL |
| **OpenBAS** | Breach & Attack Simulation (BAS) | 8082 | Java/Spring Boot |

Supporting services: PostgreSQL, Redis, Elasticsearch, RabbitMQ, MinIO, XTM Composer, 3x OpenCTI Workers.

### Nginx Routing (port 80)

| Path | Backend |
|------|---------|
| `/api/*` | Nightfall Backend (`/api/v1/*`) |
| `/opencti/*` | OpenCTI |
| `/openbas/*` | OpenBAS |
| `/*` | React SPA |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- 16GB+ RAM recommended (Elasticsearch + Java)
- Ports 80, 5432, 8081, 8082, 9200, 15672 available

### 1. Clone & Start

```bash
git clone https://github.com/shiva0126/nightfall-tsukuyomi.git
cd nightfall-tsukuyomi
docker-compose up -d
```

This starts **all 13+ containers**. First boot takes 3-5 minutes (OpenCTI and OpenBAS are slow to initialize).

### 2. Monitor Startup

```bash
# Watch container health
docker-compose ps

# Wait for all services to be healthy
docker-compose logs -f opencti openaev
```

### 3. Verify

```bash
# Nightfall API
curl http://localhost:80/api/health

# OpenCTI
curl http://localhost:80/opencti/health?health_access_key=nightfall123

# OpenBAS
curl http://localhost:80/openbas/api/health?health_access_key=nightfall123
```

### 4. Access the Platform

Open **http://localhost** in your browser.

**Login credentials:**
| Account | Email | Password |
|---------|-------|----------|
| Nightfall (demo) | `test@nightfall.local` | `password123` |
| OpenCTI admin | `admin@opencti.io` | `shiva` |
| OpenBAS admin | `admin@openaev.io` | `nightfall123` |

---

## Platform Pages

| Page | Path | Description |
|------|------|-------------|
| **Dashboard** | `/` | Overview stats — scans, findings, risk scores |
| **Discovery** | `/scan` | Unified active + passive scanner with live console |
| **Intelligence** | `/intelligence` | OpenCTI integration — threat actors, indicators, reports |
| **Findings** | `/findings` | All security findings with severity filters |
| **Validation** | `/validation` | OpenBAS integration — attack simulations & scenarios |
| **Passive Intel** | `/passive-intel` | OSINT reconnaissance from 110+ modules |
| **Reports** | `/reports` | Report generation (placeholder) |
| **Settings** | `/settings` | Platform health, API tokens, integration status |

---

## Local Development

### Backend (Go)

```bash
cd backend
go run cmd/api/main.go
# Runs on :8080 — auto-connects to localhost:5432 (fallback defaults)
```

### Frontend (React/Vite)

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev
# Runs on :5175 — proxies /api, /opencti, /openbas automatically
```

### Environment Variables

**Backend** (`backend/internal/database/database.go` — all have fallback defaults):

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `nightfall` | Database user |
| `DB_PASSWORD` | `nightfall123` | Database password |
| `DB_NAME` | `nightfall` | Database name |

**Integration** (`backend/internal/api/handlers/integration_handler.go`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCTI_URL` | `http://opencti:8080` | OpenCTI internal URL |
| `OPENCTI_TOKEN` | *(built-in)* | OpenCTI API token |
| `OPENCTI_IMPORT_CONNECTOR_ID` | `import-stix` | Connector ID used for STIX bundle imports (update this to the ID shown on OpenCTI’s Connectors page) |
| `OPENBAS_URL` | `http://openaev:8080` | OpenBAS internal URL |
| `OPENBAS_TOKEN` | *(built-in)* | OpenBAS API token |

---

## API Endpoints

### Nightfall Native

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (returns JWT) |
| POST | `/api/auth/register` | Register new user |
| GET | `/api/auth/me` | Current user info |
| POST | `/api/targets` | Create scan target |
| GET | `/api/targets` | List targets |
| POST | `/api/scans` | Start a scan |
| GET | `/api/scans` | List scans |
| GET | `/api/findings` | List findings (filterable) |
| GET | `/api/findings/stats` | Finding severity stats |
| POST | `/api/intel/passive` | Start passive recon |
| GET | `/api/intel/passive/:domain` | Get passive results |

### Integration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/integrations/status` | Health check all 3 platforms |
| GET | `/api/integrations/opencti/threats` | OpenCTI threat actors |
| GET | `/api/integrations/opencti/indicators` | OpenCTI IOCs |
| GET | `/api/integrations/openbas/simulations` | OpenBAS exercises |
| GET | `/api/integrations/openbas/scenarios` | OpenBAS scenarios |

### Re-exporting scans to OpenCTI

If you already have completed scans and want to push them into OpenCTI (for example, after a mass import or to backfill historical data), use the new command-line helper:

```bash
cd backend
go run ./cmd/export-opencti -limit 50
```

If you need to discover the connector ID, run:

```bash
cd backend
go run ./cmd/export-opencti -list-connectors
```

This prints every OpenCTI connector (ID, name, type, scope, status, execution mode); copy the ID of the STIX import connector and set `OPENCTI_IMPORT_CONNECTOR_ID` accordingly before rerunning the export helper.

Before running the helper, visit `http://localhost/opencti/connectors` (or the `/opencti/connectors` page in your deployment), copy the ID of the STIX import connector, and set it via `OPENCTI_IMPORT_CONNECTOR_ID` in your environment or `docker-compose override`. The mutation requires a valid `connectorId`, otherwise OpenCTI responds with `Field "stixBundlePush" argument "connectorId" of type "String!" is required`.

The helper exports up to `-limit` scans whose `opencti_export_status` is not `exported`. Provide `-scan-id=<id>` to target a specific scan, and adjust `-status` if you want to re-export scans with a different lifecycle state.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Go, Gin, GORM, PostgreSQL |
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, Zustand |
| **CTI Engine** | OpenCTI (Node.js, GraphQL, Elasticsearch) |
| **BAS Engine** | OpenBAS/OpenAEV (Java, Spring Boot) |
| **Infrastructure** | Docker Compose, Nginx, Redis, RabbitMQ, MinIO |

---

## Troubleshooting

**OpenBAS won't start (NullPointerException on encryption salt)**
Ensure `OPENAEV_ADMIN_ENCRYPTION_SALT` and `OPENAEV_ADMIN_ENCRYPTION_KEY` are set in docker-compose.yml. The property names use underscores, not hyphens.

**Login returns 404 (`/api/api/v1/auth/login`)**
Stale Docker image. Rebuild: `docker-compose up -d --build frontend`

**OpenCTI takes forever to start**
Normal — first boot can take 2-5 minutes. Check: `docker-compose logs -f opencti`

**xtm-composer can't connect**
Verify network name in docker-compose matches: `nightfall-tsukuyomi_nightfall-network`

---

## Legal Notice

**Authorized Use Only** — This platform is for security research, penetration testing with explicit authorization, and educational purposes only.

---

Built with Nightfall
