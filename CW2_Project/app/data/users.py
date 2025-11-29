import bcrypt
from app.data.db import get_connection

# --------------------------
# Register new user
# --------------------------
def register_user(username: str, password: str):
    """
    Create a new user and store a hashed password.
    """
    conn = get_connection()
    curr = conn.cursor()
    # hash password
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    sql = """
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
    """

    curr.execute(sql, (username, hashed))
    conn.commit()
    conn.close()

    # Also persist to a simple file store for compatibility / migration
    try:
        import os
        os.makedirs("DATA", exist_ok=True)
        users_path = os.path.join("DATA", "users.txt")

        # Read existing entries (if any) and update or append safely
        existing = {}
        if os.path.exists(users_path):
            try:
                with open(users_path, "r", encoding="utf8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(",", 1)
                        if len(parts) == 2:
                            existing[parts[0]] = parts[1]
            except Exception:
                # If reading fails, fall back to append behavior
                existing = {}

        # If user exists in file, update hash; otherwise add new entry
        existing[username] = hashed

        # Write back atomically
        tmp_path = users_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf8") as f:
                for u, h in existing.items():
                    f.write(f"{u},{h}\n")
            os.replace(tmp_path, users_path)
        except Exception:
            # If atomic replace fails, as a last resort append
            try:
                with open(users_path, "a", encoding="utf8") as f:
                    f.write(f"{username},{hashed}\n")
            except Exception:
                pass
    except Exception:
        # Do not raise on file write failure; DB insert succeeded
        pass
    

def add_user(username: str, password_hash: str):
    """Insert a user with an existing password hash. Used by migration scripts."""
    conn = get_connection()
    curr = conn.cursor()
    try:
        curr.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    finally:
        conn.close()
# --------------------------
# Get user by username
# --------------------------
def get_user_by_username(username: str):
    """
    Return one row: (id, username, password_hash) or None.
    """
    conn = get_connection()
    curr = conn.cursor()

    sql = "SELECT id, username, password_hash FROM users WHERE username = ?"
    curr.execute(sql, (username,))
    user = curr.fetchone()

    conn.close()
    return user

# --------------------------
# Check password
# --------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compare plain text password with the stored hash.
    """
    return bcrypt.checkpw(
        plain_password.encode(),
        hashed_password.encode()
    )

# --------------------------
# Helper for debugging / tests
# --------------------------
def get_all_users():
    conn = get_connection()
    curr = conn.cursor()

    sql = "SELECT id, username FROM users"
    curr.execute(sql)
    rows = curr.fetchall()

    conn.close()
    return rows