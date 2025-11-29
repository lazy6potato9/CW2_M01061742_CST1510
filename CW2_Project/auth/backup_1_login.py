import streamlit as st
from app.data.users import get_user_by_username, verify_password, register_user
from app.services.user_service import ensure_admin, ADMIN_USERNAME, ADMIN_IT_ID, reset_user_password
from session_time import login_user, is_logged_in

# Ensure admin exists
ensure_admin()

st.title("🔑 Login (backup)")

# If already logged in
if is_logged_in():
    st.success("You are already logged in.")
    st.button("Go to Dashboard", on_click=lambda: st.switch_page("pages/3_dashboard.py"))

username = st.text_input("Username")
password = st.text_input("Password", type="password")

col1, col2, col3 = st.columns([1,1,1])

with col1:
    if st.button("Login"):
        user = get_user_by_username(username)
        if user:
            user_id, db_username, password_hash = user
            if verify_password(password, password_hash):
                login_user(db_username)
                st.success("Login successful! Redirecting...")
                st.switch_page("pages/3_dashboard.py")
            else:
                st.error("Incorrect password.")
        else:
            st.error("User does not exist.")

with col2:
    if st.button("Register"):
        st.session_state['show_register'] = True

with col3:
    if st.button("Forgot password (admin only)"):
        st.session_state['show_forgot'] = True

if st.session_state.get('show_register'):
    st.subheader("Create account")
    r_user = st.text_input("New username", key="r_user")
    r_pass = st.text_input("New password", type="password", key="r_pass")
    if st.button("Create Account", key="create_acc"):
        if not r_user or not r_pass:
            st.error("Please enter both username and password.")
        else:
            # attempt to register
            register_user(r_user, r_pass)
            st.success("Account created! You can now log in.")
            st.session_state['show_register'] = False

if st.session_state.get('show_forgot'):
    st.subheader("Admin password reset")
    st.write("Only the fixed admin account can reset other users' passwords. Admin may authenticate using the fixed IT User ID.")
    admin_username = st.text_input("Admin username (fixed)", value=ADMIN_USERNAME)
    admin_itid = st.text_input("Admin IT User ID (if admin forgot password)")
    target_user = st.text_input("Username to reset")
    new_password = st.text_input("New password for user", type="password")

    if st.button("Reset password"):
        if admin_username != ADMIN_USERNAME:
            st.error("Admin username does not match fixed admin.")
        elif admin_itid != ADMIN_IT_ID:
            st.error("Invalid Admin IT ID. Only the admin with the correct IT ID can reset passwords.")
        else:
            if not target_user or not new_password:
                st.error("Enter target username and new password.")
            else:
                ok = reset_user_password(target_user, new_password)
                if ok:
                    st.success(f"Password for {target_user} reset successfully.")
                    st.session_state['show_forgot'] = False
                else:
                    st.error("Target user not found.")
