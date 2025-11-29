import streamlit as st
from main_tier3 import run_app

# Set the navigation/page title users see in the Streamlit sidebar
st.set_page_config(page_title="Home", page_icon="🏠", layout="wide")

# Run the Tier-3 app (auth/navigation handled inside)
run_app()