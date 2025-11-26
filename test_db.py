import os
import sqlite3

DB_PATH = os.path.join('DATA', 'intelligence_platform.db')
USERS_FILE = os.path.join('DATA', 'users.txt')


def get_conn(path=DB_PATH):
    # Ensure folder exists
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return sqlite3.connect(path)


def create_user_table():
    """Create the users table if it doesn't exist."""
    conn = get_conn()
    try:
        curr = conn.cursor()
        sql = (
            """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
            )"""
        )
        curr.execute(sql)
        conn.commit()
    finally:
        conn.close()


def insert_user(username, password_hash):
    """Insert a user; ignore duplicates."""
    conn = get_conn()
    try:
        curr = conn.cursor()
        sql = "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)"
        curr.execute(sql, (username, password_hash))
        conn.commit()
    except Exception as e:
        print(f"Failed to insert {username}: {e}")
    finally:
        conn.close()


def migrate_users():
    """Read `DATA/users.txt` and insert each user into the database.

    Expected file format: one user per line, `username,password_hash`.
    Lines starting with `#` or empty lines are skipped. If a line contains
    additional commas (e.g. if hashes include commas), everything after the
    first comma is treated as the hash.
    """
    if not os.path.exists(USERS_FILE):
        print(f"Users file not found: {USERS_FILE}")
        return

    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 2:
                print(f"Skipping malformed line: {line}")
                continue
            username = parts[0].strip()
            password_hash = ','.join(parts[1:]).strip()
            insert_user(username, password_hash)


def main():
    create_user_table()
    migrate_users()


if __name__ == '__main__':
    main()






