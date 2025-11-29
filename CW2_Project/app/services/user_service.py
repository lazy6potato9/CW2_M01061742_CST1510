import bcrypt
from app.data.db import get_connection

# Fixed admin credentials
ADMIN_USERNAME = "tonystanks445"
ADMIN_PASSWORD = "cptAMERICAstinks77"
ADMIN_IT_ID = "MS3659"


def add_user(username: str, password_hash: str):
	"""Insert a user row using an explicit password hash (used by migrations)."""
	conn = get_connection()
	curr = conn.cursor()
	try:
		curr.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
		conn.commit()
	finally:
		conn.close()


def ensure_admin():
	"""Ensure the fixed admin user exists in the DB. If missing, create it."""
	conn = get_connection()
	curr = conn.cursor()
	try:
		curr.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
		if not curr.fetchone():
			hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
			curr.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (ADMIN_USERNAME, hashed))
			conn.commit()
	finally:
		conn.close()


def reset_user_password(target_username: str, new_password: str) -> bool:
	"""Reset a user's password to `new_password`. Returns True if updated."""
	conn = get_connection()
	curr = conn.cursor()
	try:
		hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
		curr.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed, target_username))
		conn.commit()
		return curr.rowcount > 0
	finally:
		conn.close()

