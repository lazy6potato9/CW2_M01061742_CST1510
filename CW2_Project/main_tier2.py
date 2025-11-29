import streamlit as st
import pandas as pd
from pathlib import Path
import io
from session_time import is_logged_in, get_active_users
from typing import Any, cast


DATA_DIRS = [Path("DATA"), Path("DOCS"), Path('.')]


def find_file(name):
    for d in DATA_DIRS:
        p = d / name
        if p.exists():
            return p
    return None


def load_csv(name):
    p = find_file(name)
    if not p:
        return pd.DataFrame()
    return pd.read_csv(p)


def download_df(df, filename="export.csv"):
    if df.empty:
        return
    towrite = io.BytesIO()
    df.to_csv(towrite, index=False)
    towrite.seek(0)
    st.download_button("Download merged CSV", towrite, file_name=filename, mime='text/csv')


def run_app():
    st.set_page_config(page_title="Multi-Domain Intelligence", layout="wide")
    st.title("🧠 Multi-Domain Intelligence Platform")
    # Show onboarding instructions only when NOT logged in
    if not is_logged_in():
        st.markdown("## Welcome")
        st.subheader("What you can do:")
        st.markdown(
            "- 🔐  Secure login and admin-managed password resets  \n"
            "- 📊  View domain dashboards (Cyber, Datasets, IT Tickets)  \n"
            "- 🔗  Integrate data across domains with selectable heuristics  \n"
            "- ⬇️  Export merged results to CSV"
        )

    # Load two domains: Cyber incidents and Datasets metadata
    df_cyber = load_csv("cyber_incidents.csv")
    df_datasets = load_csv("datasets_metadata.csv")

    sidebar = st.sidebar
    sidebar.header("Navigation")
    # If not logged in only show Login/Register
    if not is_logged_in():
        page = sidebar.radio("Page", ["Login", "Register"]) 
        st.info("Please login or register to access the dashboard.")
        return

    # When logged in, immediately redirect to the full dashboard page
    try:
        st.switch_page("pages/3_dashboard.py")
        st.stop()
    except Exception:
        # If switch_page is not available for some Streamlit versions, just show a link
        st.info("Dashboard is available — please use the app navigation to open the dashboard.")
        return

    # When logged in the app redirects to the full dashboard page (see pages/3_dashboard.py).
    # Additional per-page UI used previously has been moved to the dedicated dashboard page.


if __name__ == "__main__":
    run_app()
