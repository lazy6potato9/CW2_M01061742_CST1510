# Multi-Domain Intelligence Platform (Streamlit)

A local Streamlit scaffold providing secure login, three domain dashboards (Cyber, Data Science, IT Operations), and cross-domain integration with multiple heuristics. The app reads sample CSVs from `DATA/` and `DOCS/`, supports file-based user storage, and exports merged results to CSV.

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
cd CW2_Project
python -m streamlit run home.py --server.port 8502
```

Open `http://localhost:8502` in your browser. (If port 8502 is in use, try `--server.port 8505` or another free port.)

## Features

- **🔐 Secure Authentication** — Passwords stored as salted bcrypt hashes; sessions are ephemeral (log out on refresh).
- **📊 Three Domain Dashboards** — Cyber incidents, Datasets metadata, and IT Tickets with summary charts and detailed views.
- **🧩 Multi-Heuristic Integration** — Exact joins, fuzzy description matching, nearest-timestamp merging, and auto cross-linking across three domains.
- **⬇️ CSV Export** — Download merged results directly from the UI.
- **👤 Admin Panel** — Manage user passwords via secure IT ID verification.

## Default Admin Credentials (Testing Only)

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `ChangeMe!2025` |
| Admin IT ID | `MS3659` |

⚠️ **Security Warning:** Change these credentials immediately after first login. Do not commit them to public repositories.

## Project Structure

```
CW2_Project/
├── home.py                 # Main app entrypoint (auth + dashboards + integration)
├── session_time.py         # Session and active-user tracking
├── app/
│   ├── data/
│   │   ├── users.py       # User registration, password hashing/verification
│   │   ├── incidents.py   # Cyber incident data models
│   │   ├── tickets.py     # IT ticket models
│   │   └── datasets.py    # Dataset metadata models
│   └── services/
│       └── user_service.py # Admin utilities (password reset, IT ID verification)
└── DATA/
    ├── intelligence_platform.db  # User credentials (auto-created)
    ├── cyber_incidents.csv       # Cyber domain sample data
    ├── datasets_metadata.csv     # Dataset domain sample data
    └── it_tickets.csv            # IT Tickets domain sample data
```

## Using the App

### Login & Registration
- Click **Login** in the sidebar to authenticate.
- Click **Register** to create a new user account.
- Password policy: minimum 6 chars, at least one uppercase, one lowercase, one digit, one special character.

### Dashboard Tabs (when logged in)
1. **Cyber** — Incident records with severity breakdown and incident-type distribution.
2. **Datasets** — Metadata and record counts per dataset.
3. **Tickets** — IT ticket records with priority distribution.
4. **Active Users** — Real-time count of logged-in users (admin-only expanded view).
5. **Integration** — Advanced heuristics for merging across domains.

### Integration Heuristics

Choose from:
- **Exact common-key join** — Merges on shared columns across all three domains.
- **Description substring match** — Fuzzy matches incident/ticket descriptions.
- **Nearest timestamp (days)** — Joins records within a configurable time window.
- **Auto cross-link (three-way)** — Automatically attempts all heuristics and reports which succeeded.
- **Fuzzy pairwise match** — Text-similarity-based matching between two domains.
- **Fuzzy three-way attach** — Fuzzy incidents↔tickets, then attaches datasets by name substring.
- **Manual three-way cross-link** — Inspect schemas and manually select join columns.

## Authentication & Security

- **Password Storage** — Bcrypt hashing with salt; plaintext passwords never stored.
- **Sessions** — Ephemeral; refreshing the page logs out the user.
- **Admin Reset Flow** — Only users with the correct **Admin IT ID** can reset other users' passwords via the sidebar.
- **File-Based User Store** — Stored in `DATA/intelligence_platform.db` (SQLite).

## Data Files

**Sample CSV files** (place in `DATA/` or `DOCS/`):
- `cyber_incidents.csv` — Columns: `id`, `severity`, `incident_type`, `description`, etc.
- `datasets_metadata.csv` — Columns: `dataset_name`, `name`, `records`, etc.
- `it_tickets.csv` — Columns: `id`, `priority`, `status`, `description`, etc.

The app auto-detects and loads these files from multiple search paths.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port in use | Try `--server.port 8505` or another free port. |
| Code changes not reflected | Restart the Streamlit process. |
| Login fails | Ensure `DATA/intelligence_platform.db` exists and is readable. |
| CSV not found | Place files in `DATA/` or `DOCS/` subdirectories. |

## Extending the App

- **Add new data domains** — Create models in `app/data/` and import them in `home.py`.
- **Replace file-based storage** — Swap `users.py` to use a real database (PostgreSQL, MySQL, etc.).
- **Custom heuristics** — Edit the integration functions in `home.py` to add new merge strategies.

## Notes

- Tier 2 (prototype) has been removed; only the full-featured `home.py` is maintained.
- The old `main.py` entry point has been deleted for clarity.
- All Streamlit-recommended best practices are followed (state management, session caching, etc.).

---

Last updated: 2025-12-12

