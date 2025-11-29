import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

from session_time import is_logged_in, logout_user, get_active_users
from app.services.user_service import ADMIN_USERNAME


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


# Minimal page header
st.title("Multi-Domain Intelligence Platform")

if not is_logged_in():
    st.warning("You must log in to view the Dashboard")
    st.stop()

# Sidebar: show current user and logout
st.sidebar.markdown(f"**Logged in:** {st.session_state.get('user')}")
if st.sidebar.button("Logout"):
    logout_user()
    st.rerun()

# Active users (admin gets full list)
st.sidebar.markdown("---")
st.sidebar.header("Active Users")
active = get_active_users()
current = st.session_state.get('user')
if current == ADMIN_USERNAME:
    if active:
        for u in active:
            st.sidebar.write(f"- {u}")
    else:
        st.sidebar.write("No active users")
else:
    st.sidebar.write("(admin only)")

# Dashboard content: overview + infographics (copied from main)
st.header("Overview — three domains")
df_cyber = load_csv("cyber_incidents.csv")
df_datasets = load_csv("datasets_metadata.csv")
df_tickets = load_csv("it_tickets.csv")

col1, col2, col3 = st.columns(3)
col1.metric("Cyber rows", str(len(df_cyber)))
col2.metric("Datasets rows", str(len(df_datasets)))
col3.metric("Tickets rows", str(len(df_tickets)))

with st.container():
    st.subheader("Cyber — key visuals")
    if not df_cyber.empty:
        candidates = [c for c in ["severity", "incident_type", "type", "category"] if c in df_cyber.columns]
        if candidates:
            col = candidates[0]
            counts = df_cyber[col].fillna("(unknown)").astype(str).value_counts()
            fig = px.bar(x=counts.index, y=counts.values, labels={'x': col, 'y': 'count'}, title=f"Cyber by {col}")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No categorical column found in Cyber for breakdown")
    else:
        st.info("No Cyber data available for visuals")

with st.container():
    st.subheader("Tickets — key visuals")
    if not df_tickets.empty:
        t_cands = [c for c in ["priority", "status", "state"] if c in df_tickets.columns]
        if t_cands:
            tcol = t_cands[0]
            tcounts = df_tickets[tcol].fillna("(unknown)").astype(str).value_counts()
            fig2 = px.pie(values=tcounts.values, names=tcounts.index, title=f"Tickets by {tcol}")
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No ticket categorical column found for visuals")
    else:
        st.info("No Tickets data available for visuals")

with st.container():
    st.subheader("Datasets — key visuals")
    if not df_datasets.empty:
        d_cands = [c for c in ["dataset_name", "name", "title"] if c in df_datasets.columns]
        if d_cands:
            dcol = d_cands[0]
            dcounts = df_datasets[dcol].fillna("(unknown)").astype(str).value_counts().nlargest(10)
            fig3 = px.bar(x=dcounts.index, y=dcounts.values, labels={'x': dcol, 'y': 'count'}, title=f"Top {len(dcounts)} Datasets")
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.metric("Datasets total", str(len(df_datasets)))
    else:
        st.info("No Datasets data available for visuals")
import streamlit as st
import pandas as pd
import plotly.express as px

from session_time import is_logged_in, logout_user, get_active_users
from app.services.user_service import ADMIN_USERNAME
from app.data.incidents import load_incidents
from app.data.datasets import load_datasets_metadata
from app.data.tickets import load_it_tickets


# Main heading (always visible)
st.title("🧠 Multi-Domain Intelligence Platform")

# If not logged in show the requested message and stop
if not is_logged_in():
    st.warning("You have been watched — please log in through the secure system")
    st.stop()

# Hide Streamlit's main menu/footer for authenticated users so
# navigation links to login/register are not visible after login.
# NOTE: keep the `header` visible so the built-in sidebar toggle works.
st.markdown(
    """
    <style>
    /* hide the hamburger menu / page-nav (three-dot menu) */
    #MainMenu {visibility: hidden;}
    /* hide the footer */
    footer {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.header("📊 Intelligence Dashboard")

# Show current logged in user and logout + logout action that redirects
st.sidebar.markdown(f"**Logged in:** {st.session_state.get('user')} ")

def _do_logout():
    # call existing helper to clear session and active-users file
    # Clear session and record that a logout just happened.
    # We avoid performing navigation inside the callback because Streamlit
    # will internally call `st.rerun()` and warn when that happens inside
    # a widget callback. Instead we set a session flag and handle the
    # navigation during the normal script run (below).
    logout_user()
    st.session_state["_just_logged_out"] = True

st.sidebar.button("Logout", on_click=_do_logout, use_container_width=True)

# If a logout was requested by the callback above, handle navigation here
# (this runs during the normal script execution, not inside the widget
# callback, so Streamlit's rerun behavior is safe and will not emit the
# "Calling st.rerun() within a callback is a no-op." warning).
if st.session_state.pop("_just_logged_out", False):
    st.success("You have been logged out.")
    try:
        st.switch_page("main.py")
        st.stop()
    except Exception:
        st.info("Please return to the app home to log in again.")
        st.stop()

# Active users listing in sidebar (admin only)
st.sidebar.markdown("---")
st.sidebar.header("Active Users")
active = get_active_users()
# Only show active user list to the fixed admin account
current = st.session_state.get('user')
if current == ADMIN_USERNAME:
    if active:
        for u in active:
            st.sidebar.write(f"- {u}")
    else:
        st.sidebar.write("No active users")
else:
    st.sidebar.write("(admin only)")

# ----------------------------
# TABS
# ----------------------------
tab1, tab2, tab3 = st.tabs([
    "🛡 Cybersecurity Incidents",
    "📚 Dataset Metadata",
    "🧾 IT Ticket Analytics"
])

# ===============================================================
# TAB 1 — CYBER INCIDENTS
# ===============================================================
with tab1:
    st.subheader("Cybersecurity Incidents")

    # Load from DB with CSV fallback (use CSV files if DB table empty)
    try:
        df = load_incidents()
    except Exception:
        df = pd.DataFrame()

    if df.empty:
        try:
            df = pd.read_csv("DATA/cyber_incidents.csv")
        except Exception:
            df = pd.DataFrame()

    # Metrics (guard against missing columns)
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Incidents", len(df))
    if "severity" in df.columns:
        try:
            critical_count = int((df["severity"] == "Critical").sum())
        except Exception:
            critical_count = "N/A"
    else:
        critical_count = "N/A"
    col2.metric("Critical", critical_count)

    if "incident_type" in df.columns:
        try:
            phishing_count = int((df["incident_type"] == "Phishing").sum())
        except Exception:
            phishing_count = "N/A"
    else:
        phishing_count = "N/A"
    col3.metric("Phishing", phishing_count)

    st.write("### Incident Records")
    if df.empty:
        st.info("No incident records available (DB table empty and CSV missing).")
    else:
        st.dataframe(df)

        # Chart: Severity (only if column exists)
        if "severity" in df.columns:
            st.write("### Incidents by Severity")
            st.bar_chart(df["severity"].value_counts())

        # Chart: Incident Types (Pie) if present
        if "incident_type" in df.columns:
            fig = px.pie(df, names="incident_type", title="Incident Type Distribution")
            st.plotly_chart(fig)

# ===============================================================
# TAB 2 — DATASET METADATA
# ===============================================================
with tab2:
    st.subheader("Dataset Metadata Overview")

    try:
        df_meta = load_datasets_metadata()
    except Exception:
        df_meta = pd.DataFrame()

    if df_meta.empty:
        try:
            df_meta = pd.read_csv("DATA/datasets_metadata.csv")
        except Exception:
            df_meta = pd.DataFrame()

    st.write("### Raw Metadata")
    if df_meta.empty:
        st.info("No dataset metadata available (DB table empty and CSV missing).")
    else:
        st.dataframe(df_meta)

        # Records chart
        if "dataset_name" in df_meta.columns and "records" in df_meta.columns:
            st.write("### Dataset Size Comparison")
            fig_meta = px.bar(df_meta, x="dataset_name", y="records",
                              title="Record Count per Dataset")
            st.plotly_chart(fig_meta)

# ===============================================================
# TAB 3 — IT TICKETS
# ===============================================================
with tab3:
    st.subheader("IT Ticket Analytics")

    try:
        df_tickets = load_it_tickets()
    except Exception:
        df_tickets = pd.DataFrame()

    if df_tickets.empty:
        try:
            df_tickets = pd.read_csv("DATA/it_tickets.csv")
        except Exception:
            df_tickets = pd.DataFrame()

    st.write("### Ticket Records")
    if df_tickets.empty:
        st.info("No IT ticket records available (DB table empty and CSV missing).")
    else:
        st.dataframe(df_tickets)

        # Bar chart of priorities
        if "priority" in df_tickets.columns:
            st.write("### Tickets by Priority")
            fig_t = px.bar(df_tickets["priority"].value_counts(),
                           title="Priority Distribution")
            st.plotly_chart(fig_t)