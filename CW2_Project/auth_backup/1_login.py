import streamlit as st
from session_time import is_logged_in

# Deprecated page stub
# The auth UI has moved into the app entry (`main.py`).
if is_logged_in():
    try:
        st.info("You are authenticated — redirecting to Dashboard...")
        st.switch_page("pages/3_dashboard.py")
    except Exception:
        st.info("You are authenticated. Open the Dashboard from the app navigation.")
else:
    try:
        st.info("Authentication is now handled on the main app entry. Please return to the app home page.")
        st.switch_page("main.py")
    except Exception:
        st.info("Authentication moved to the main app entry.")

st.stop()