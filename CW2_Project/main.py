"""
main.py — Entry selector (now single variant)

Tier 2 has been removed. This file simply loads the full-featured app (previously Tier 3),
which now lives in home.py.
"""

# Ensure Streamlit page config is set early so headings render correctly
import streamlit as st

from app.services.user_service import ensure_admin, ADMIN_USERNAME, ADMIN_IT_ID, reset_user_password
from app.data.users import get_user_by_username, verify_password, register_user
from session_time import login_user, is_logged_in
from home import run_app as run_variant


def _show_auth_ui():
    # Set page config early for consistent rendering
    st.set_page_config(page_title="Multi-Domain Intelligence (Auth)", layout="wide")
    st.title("🛡️ Multi-Domain Intelligence Platform")
    st.subheader("Sign in to access the Intelligence Dashboard — view domain dashboards, integrate data across domains, and export results.")

    # (sidebar toggle removed)

    # Login box with register inside an expander
    username = st.text_input("Username", key="auth_username")
    password = st.text_input("Password", type="password", key="auth_password")
    if st.button("Login"):
        user = get_user_by_username(username)
        if user:
            _id, db_username, password_hash = user
            if verify_password(password, password_hash):
                login_user(db_username)
                st.success("Login successful — redirecting to dashboard...")
                try:
                    st.switch_page("pages/3_dashboard.py")
                    st.stop()
                except Exception:
                    st.success("Login succeeded. Use the button below to open the Dashboard.")
                    if st.button("Open Dashboard"):
                        try:
                            st.switch_page("pages/3_dashboard.py")
                        except Exception:
                            st.warning("Please open the Dashboard from the app navigation.")
            else:
                st.error("Incorrect password.")
        else:
            st.error("User not found.")

    with st.expander("Create an account"):
        r_user = st.text_input("New username", key="reg_user")
        r_pass = st.text_input("New password", type="password", key="reg_pass")
        st.write("Password must be at least 6 chars and include upper/lower/number/special.")
        if st.button("Create Account"):
            if not r_user or not r_pass:
                st.error("Enter username and password.")
            elif get_user_by_username(r_user):
                st.error("Username already exists.")
            else:
                # basic client-side validation
                missing = []
                if len(r_pass) < 6:
                    missing.append("at least 6 chars")
                if not any(c.isupper() for c in r_pass):
                    missing.append("an uppercase")
                if not any(c.islower() for c in r_pass):
                    missing.append("a lowercase")
                if not any(c.isdigit() for c in r_pass):
                    missing.append("a number")
                if not any(not c.isalnum() for c in r_pass):
                    missing.append("a special character")
                if missing:
                    st.error("Password missing: " + ", ".join(missing))
                else:
                    register_user(r_user, r_pass)
                    st.success("Account created. You can now log in.")

    with st.expander("Admin: Reset user password (admin only)"):
        st.write("Only the fixed admin account can reset other users' passwords. Admin authenticates using the fixed IT User ID.")
        admin_username = st.text_input("Admin username (fixed)", value=ADMIN_USERNAME, key="admin_user")
        admin_itid = st.text_input("Admin IT User ID", key="admin_itid")
        target_user = st.text_input("Target username to reset", key="admin_target")
        new_password = st.text_input("New password for target", type="password", key="admin_newpw")
        if st.button("Reset password", key="admin_reset"):
            if admin_username != ADMIN_USERNAME:
                st.error("Admin username does not match fixed admin.")
            elif admin_itid != ADMIN_IT_ID:
                st.error("Invalid Admin IT ID. Only the admin with the correct IT ID can reset passwords.")
            else:
                if not target_user or not new_password:
                    st.error("Enter a target username and a new password.")
                else:
                    ok = reset_user_password(target_user, new_password)
                    if ok:
                        st.success(f"Password for {target_user} has been reset.")
                    else:
                        st.error("Target user not found or update failed.")


if __name__ == "__main__":
    # Ensure admin exists before app starts
    try:
        ensure_admin()
    except Exception:
        pass

    # If already logged in, immediately run the dashboard variant
    if is_logged_in():
        run_variant()
    else:
        _show_auth_ui()