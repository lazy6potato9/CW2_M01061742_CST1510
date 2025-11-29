import sqlite3
import os

DB_PATH = "DATA/intelligence_platform.db"


def _initialize_db(path: str):
    """Create the database file and required tables if they don't exist.

    This function runs DDL directly to avoid import-time circular
    dependencies with `app.data.schema` which itself imports
    `get_connection()`.
    """
    # ensure parent directory exists
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    # Connect (this creates the file if needed) and ensure tables exist
    conn = sqlite3.connect(path)
    try:
        curr = conn.cursor()

        # USERS TABLE
        curr.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)

        # CYBER INCIDENTS
        curr.execute("""
            CREATE TABLE IF NOT EXISTS cyber_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT,
                severity TEXT,
                date TEXT,
                description TEXT
            );
        """)

        # DATASETS METADATA
        curr.execute("""
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_name TEXT,
                domain TEXT,
                records INTEGER
            );
        """)

        # IT TICKETS
        curr.execute("""
            CREATE TABLE IF NOT EXISTS it_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT,
                category TEXT,
                priority TEXT,
                status TEXT,
                created_at TEXT
            );
        """)

        conn.commit()
    finally:
        conn.close()


def get_connection():
    """Opens and returns a connection to the SQLite database.

    If the database file does not exist yet, it will be created and the
    required tables will be initialized.
    """
    # Make sure the DATA folder exists and initialize DB if missing
    os.makedirs("DATA", exist_ok=True)

    # Always connect, then ensure tables exist. This covers the case where
    # the DB file exists but tables were not created previously.
    conn = sqlite3.connect(DB_PATH)
    try:
        curr = conn.cursor()

        # USERS TABLE
        curr.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)

        # CYBER INCIDENTS
        curr.execute("""
            CREATE TABLE IF NOT EXISTS cyber_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT,
                severity TEXT,
                date TEXT,
                description TEXT
            );
        """)

        # DATASETS METADATA
        curr.execute("""
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_name TEXT,
                domain TEXT,
                records INTEGER
            );
        """)

        # IT TICKETS
        curr.execute("""
            CREATE TABLE IF NOT EXISTS it_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT,
                category TEXT,
                priority TEXT,
                status TEXT,
                created_at TEXT
            );
        """)

        conn.commit()
    finally:
        # Return a new connection for callers (close the temp one first)
        conn.close()

    return sqlite3.connect(DB_PATH)














'''import sqlite3
import pandas as pd

#---------------------------get data------------------------------
def get_all_cyber_incidents(conn):
    sql = 'SELECT * from cyber_incidents'
    data = pd.read_sql(sql, conn)
    return data 

conn = sqlite3.connect('app/data/cyber_incidents.db')'''