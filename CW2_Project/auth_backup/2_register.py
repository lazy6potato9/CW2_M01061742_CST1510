import streamlit as st
from session_time import is_logged_in

# Deprecated registration page — registration is now handled at the main app entry (`main.py`).
if is_logged_in():
    try:
        st.info("You are authenticated — redirecting to Dashboard...")
        st.switch_page("pages/3_dashboard.py")
    except Exception:
        st.info("You are authenticated. Open the Dashboard from the app navigation.")
else:
    try:
        st.info("Registration is now handled at the main app entry. Please return to the app home page.")
        st.switch_page("main.py")
    except Exception:
        st.info("Registration moved to the main app entry.")

st.stop()