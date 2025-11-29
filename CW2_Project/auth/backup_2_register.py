import streamlit as st
from app.data.users import register_user, get_user_by_username

st.title("📝 Register (backup)")

st.info("Password requirements: at least 6 characters, including 1 uppercase, 1 lowercase, 1 number, and 1 special character.")

username = st.text_input("Choose a username")
password = st.text_input("Choose a password", type="password")


def validate_password(pw: str):
    missing = []
    if len(pw) < 6:
        missing.append("at least 6 characters")
    if not any(c.isupper() for c in pw):
        missing.append("an uppercase letter")
    if not any(c.islower() for c in pw):
        missing.append("a lowercase letter")
    if not any(c.isdigit() for c in pw):
        missing.append("a number")
    if not any(not c.isalnum() for c in pw):
        missing.append("a special character")
    return missing


if st.button("Create Account"):
    if not username or not password:
        st.error("Please enter both username and password.")
    else:
        # Check if user exists
        if get_user_by_username(username):
            st.error("This username already exists.")
        else:
            missing = validate_password(password)
            if missing:
                st.error("Password does not meet requirements: " + ", ".join(missing))
            else:
                register_user(username, password)
                st.success("Account created! You can now log in.")
