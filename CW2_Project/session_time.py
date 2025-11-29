import streamlit as st
from pathlib import Path

ACTIVE_USERS_FILE = Path("DATA") / "active_users.txt"

def login_user(username):
    """Store logged-in user in session."""
    st.session_state["user"] = username
    # Do NOT persist the logged-in user to disk. This ensures a browser
    # refresh does not silently re-authenticate the user (auto-logout on refresh).
    # record active user
    try:
        ACTIVE_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # append username if not already present
        existing = []
        if ACTIVE_USERS_FILE.exists():
            existing = [l.strip() for l in ACTIVE_USERS_FILE.read_text().splitlines() if l.strip()]
        if username not in existing:
            with ACTIVE_USERS_FILE.open("a", encoding="utf8") as f:
                f.write(username + "\n")
    except Exception:
        # do not break login if file operations fail
        pass

def logout_user():
    """Clear user session."""
    username = st.session_state.get("user")
    st.session_state.clear()
    # no on-disk persistence to remove
    # remove from active users file
    try:
        if ACTIVE_USERS_FILE.exists() and username:
            lines = [l for l in ACTIVE_USERS_FILE.read_text().splitlines() if l.strip() and l.strip() != username]
            ACTIVE_USERS_FILE.write_text("\n".join(lines))
    except Exception:
        pass

def is_logged_in():
    """Check if user logged in."""
    # Only consider the session logged in if the session state contains the user.
    # This means a full page refresh (which clears session_state) will require
    # the user to log in again.
    return "user" in st.session_state

def require_login():
    """Redirect users who are NOT logged in."""
    if not is_logged_in():
        st.warning("You must log in first.")
        st.switch_page("Home.py")


def get_active_users():
    try:
        if ACTIVE_USERS_FILE.exists():
            return [l.strip() for l in ACTIVE_USERS_FILE.read_text().splitlines() if l.strip()]
    except Exception:
        pass
    return []