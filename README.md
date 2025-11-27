# Cyber Intelligence Platform

A Streamlit-based Cyber Intelligence Platform for viewing cybersecurity incidents, dataset metadata, and IT ticket analytics. Includes simple user registration/login backed by a local SQLite database.

## Contents
- `main.py` — Streamlit app entry point (landing page + links to pages).
- `pages/` — multi-page UI:
  - `1_login.py`, `2_register.py`, `3_dashboard.py`.
- `session_time.py` — session helpers (login/logout/is_logged_in).
- `app/data/` — data loading modules for datasets, incidents, tickets, users, and DB access.
- `DATA/` — CSV datasets and `users.txt` and the SQLite DB `intelligence_platform.db`.
- `test_db.py` — script that creates the `users` table and migrates `DATA/users.txt` into the DB.

## Quick start (Windows, cmd.exe)

1. Create a virtual environment (recommended):

   ```cmd
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies:

   - If you have a complete `requirements.txt`:

     ```cmd
     pip install -r requirements.txt
     ```

   - Otherwise, install the essentials used by the project:

     ```cmd
     pip install streamlit pandas plotly
     ```

3. Prepare the database (migrate users):

   ```cmd
   python test_db.py
   ```

   This creates `DATA/intelligence_platform.db` and inserts users from `DATA/users.txt`.

4. Run the app:

   ```cmd
   streamlit run main.py --server.port 8501
   ```

   Open your browser at `http://localhost:8501`.

## Files and data

- `DATA/` contains sample data files used by the app:
  - `cyber_incidents.csv`, `datasets_metadata.csv`, `it_tickets.csv`, `users.txt`.
- The app loads data from these files via modules in `app/data/`.

## Troubleshooting

- If a `ModuleNotFoundError` appears for a package (e.g. `plotly`), install it:

  ```cmd
  pip install plotly
  pip freeze > requirements.txt
  ```

- If port `8501` is already in use, find and stop the process before restarting:

  ```cmd
  netstat -ano | findstr :8501
  taskkill /PID <PID> /F
  ```

- `.venv/` is ignored by Git (see `.gitignore`). Deleting `.venv` will remove the local virtual environment files:

  ```cmd
  rmdir /s /q .venv
  ```

## Development notes

- Keep page filenames consistent (lowercase in this repo). Use the exact filename in `st.page_link()` or `st.switch_page()` to avoid cross-platform issues.
- Passwords should always be stored hashed. This repo expects hashed passwords in `DATA/users.txt`; `app/data/users.py` should use a secure hashing library (bcrypt recommended).

## Next steps / recommended improvements

- Add a full `requirements.txt` (run `pip freeze > requirements.txt`).
- Add a `README.md` section showing example credentials (if you include test users) or create a script to generate test users.
- Add unit tests for data loaders and small CI checks to lint and run tests on push.

## Contact

If you want me to (pick one):
- generate a full `requirements.txt`,
- stop the running Streamlit server, or
- add a short `CONTRIBUTING.md` with development instructions.
