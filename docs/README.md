# Multi-Domain Intelligence Platform (Streamlit)

A local Streamlit scaffold providing secure login, three domain dashboards (Cyber, Data Science, IT Operations), and a cross-domain integration view. This repository is a self-contained demo that reads sample CSVs from `DOCS/` and supports file-based user storage in `DATA/users.txt`.

## Features
- Secure authentication using bcrypt and a small file-based user store.
- Admin account with IT-ID reset flow.
- Sidebar navigation with pages: Dashboard, Cyber, Data Science, IT Operations, Integration.
- Dashboard with overview KPIs and CSV-backed tables for Cyber incidents, Datasets metadata, and Tickets.
- Integration page showing cross-domain correlations and a conservative heuristic merge (exact keys, common columns, description substring, nearest timestamp).

## Prerequisites
- Python 3.10+ (recommended).
- Git (optional) to clone repository.

## Quick Setup (Windows - cmd.exe)
1. Create and activate a virtual environment (recommended):

```cmd
python -m venv .venv
.venv\Scripts\activate
```

2. Install required packages:

```cmd
pip install streamlit pandas bcrypt pyarrow
```

3. (Optional) If you prefer, create a `requirements.txt` with the above packages and run `pip install -r requirements.txt`.

## Run the app
From the repository root (where `main.py` lives) run:

```cmd
.venv\Scripts\python -m streamlit run main.py --server.port 8504
```

Open the Local URL printed by Streamlit (e.g. `http://localhost:8504`).

## Default admin credentials
- Username: `iambrucepain990`
- Password: `IRONMANSUCKS69`
- Admin IT ID (for reset flow): `MS3659`

The admin account is persisted automatically into `DATA/users.txt` on first run.

## Using the app
- Login or Register using the sidebar.
- After login you will be redirected automatically to the Dashboard.
- Dashboard tabs present Overview charts and the CSV tables for Cyber incidents, Datasets metadata, and Tickets.
- Integration page attempts a conservative cross-domain merge and displays which heuristic was used and how many matches were found; if no merge is possible the page shows recent samples from each domain.

## Data files
- Sample CSVs are in `DOCS/`:
  - `cyber_incidents.csv`
  - `datasets_metadata.csv`
  - `it_tickets.csv`
- App data and logs are stored in `DATA/` (including `users.txt`, `login_attempts.log`, and `admin_verify.log`).

## How integration works (brief)
- The app prefers exact key joins (e.g., `incident_id` ↔ `id`) when present.
- If no explicit keys match, it tries reasonable alternatives (shared column names), then a description-substring heuristic, and finally a nearest-timestamp merge (within a configurable tolerance).
- The chosen heuristic and counts of matched/unmatched rows are presented on the Integration page for transparency.

## Admin tasks
- To add an admin or reset the admin password using the IT ID flow, use the "Forgot Password (admin only)" button on the Login page.
- To inspect or edit registered users directly, see `DATA/users.txt` (format `username|bcrypt_hash`). Editing this file manually is not recommended unless you understand bcrypt hashes.

## Troubleshooting
- If the server reports a port-in-use error, pass a different port to Streamlit (for example `--server.port 8505`).
- If pages do not reflect recent code edits, restart the Streamlit process.

## Extending the app
- Add new CSVs or database connectors and update `app/data/*.py` helpers.
- You can replace the file-based user store with a proper database by swapping the `read_users`, `write_users`, and `ensure_users_file` implementations in `main.py`.

## Contact / Next steps
- If you'd like me to (A) add a UI to choose join keys, (B) export merged results to CSV, or (C) tighten the integration heuristics, tell me which option and I will implement it.

---
Happy testing — open `http://localhost:8504` after starting the app.

