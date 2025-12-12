import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
import io
from datetime import timedelta
from session_time import is_logged_in, get_active_users, login_user
from app.data.users import register_user, get_user_by_username, verify_password
from app.services.user_service import ensure_admin, ADMIN_USERNAME, ADMIN_IT_ID, reset_user_password
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


def fuzzy_description_merge(left, right, left_col, right_col):
	# Simple substring matching - returns left rows with a matching right row.
	matches = []
	r_texts = right[right_col].fillna("").astype(str)
	for i, lrow in left.iterrows():
		ltxt = str(lrow.get(left_col, ""))
		found = None
		for j, rtxt in r_texts.iteritems():
			if not pd.isna(rtxt) and ltxt.lower() in rtxt.lower() or rtxt.lower() in ltxt.lower():
				found = right.loc[j]
				break
		if found is not None:
			merged = pd.concat([lrow.to_frame().T.reset_index(drop=True), found.to_frame().T.reset_index(drop=True)], axis=1)
			matches.append(merged)
	if not matches:
		return pd.DataFrame()
	return pd.concat(matches, ignore_index=True)


def nearest_timestamp_merge(left, right, left_ts, right_ts, tolerance_days=1):
	# Ensure parsed datetimes
	left_ts_s = pd.to_datetime(left[left_ts], errors='coerce')
	right_ts_s = pd.to_datetime(right[right_ts], errors='coerce')
	right_idx = right_ts_s.dropna().index
	rows = []
	tol = pd.Timedelta(days=tolerance_days)
	for i, ltime in left_ts_s.dropna().items():
		diffs = (right_ts_s - ltime).abs()
		if diffs.empty:
			continue
		j = diffs.idxmin()
		if diffs.loc[j] <= tol:
			rows.append(pd.concat([left.loc[i].to_frame().T.reset_index(drop=True), right.loc[j].to_frame().T.reset_index(drop=True)], axis=1))
	if not rows:
		return pd.DataFrame()
	return pd.concat(rows, ignore_index=True)


def crosslink_three_way(df1, df2, df3):
	"""Attempt to produce a three-way cross-linked table using several heuristics.

	Strategies (in order):
	1. Exact three-way join on a single common column present in all three.
	2. Pairwise exact joins (try df1+df2 then join df3, and permutations).
	3. Fuzzy description match between pairs (if text columns available), then join the third.
	4. Nearest-timestamp pairwise join (if timestamp columns exist), then join the third.

	Returns a DataFrame (possibly empty) and a short message describing the method used.
	"""
	# Helper to find common columns
	def common_cols(a, b):
		return list(set(a.columns) & set(b.columns))

	# 1) exact three-way
	common_all = set(df1.columns) & set(df2.columns) & set(df3.columns)
	if common_all:
		key = list(common_all)[0]
		try:
			m = pd.merge(df1, df2, on=key, how='inner')
			m = pd.merge(m, df3, on=key, how='inner')
			return m, f"Exact three-way on '{key}'"
		except Exception:
			pass

	# 2) pairwise exact joins in permutations
	from itertools import permutations
	for a, b, c in permutations([(df1, 'df1'), (df2, 'df2'), (df3, 'df3')], 3):
		A, _ = a
		B, _ = b
		C, _ = c
		commons = common_cols(A, B)
		if commons:
			key = commons[0]
			try:
				m12 = pd.merge(A, B, on=key, how='inner')
				commons3 = common_cols(m12, C)
				if commons3:
					key2 = commons3[0]
					m123 = pd.merge(m12, C, on=key2, how='inner')
					if not m123.empty:
						return m123, f"Pairwise exact joins on '{key}' then '{key2}'"
			except Exception:
				continue

	# 3) fuzzy description between pairs
	text_candidates = lambda df: [c for c in df.columns if df[c].dtype == object and df[c].astype(str).str.len().mean() > 0]
	# try fuzzy between df1 and df3, then join df2
	for left, right, third in [(df1, df3, df2), (df1, df2, df3), (df2, df3, df1)]:
		left_texts = text_candidates(left)
		right_texts = text_candidates(right)
		if left_texts and right_texts:
			lcol = left_texts[0]
			rcol = right_texts[0]
			try:
				m = fuzzy_description_merge(left, right, lcol, rcol)
				if not m.empty:
					commons_with_third = list(set(m.columns) & set(third.columns))
					if commons_with_third:
						k = commons_with_third[0]
						m123 = pd.merge(m, third, on=k, how='inner')
						if not m123.empty:
							return m123, f"Fuzzy match on {lcol}<->{rcol} then join on '{k}'"
			except Exception:
				pass

	# 4) nearest-timestamp pairwise
	time_like = lambda df: [c for c in df.columns if 'time' in c.lower() or 'date' in c.lower() or 'timestamp' in c.lower()]
	for left, right, third in [(df1, df3, df2), (df1, df2, df3), (df2, df3, df1)]:
		ltimes = time_like(left)
		rtimes = time_like(right)
		if ltimes and rtimes:
			try:
				m = nearest_timestamp_merge(left, right, ltimes[0], rtimes[0], tolerance_days=1)
				if not m.empty:
					commons_with_third = list(set(m.columns) & set(third.columns))
					if commons_with_third:
						k = commons_with_third[0]
						m123 = pd.merge(m, third, on=k, how='inner')
						if not m123.empty:
							return m123, f"Nearest-timestamp match on {ltimes[0]}<->{rtimes[0]} then join on '{k}'"
			except Exception:
				pass

	# Failed to produce a cross-linked table
	return pd.DataFrame(), "No cross-link produced by heuristics"


def fuzzy_pairwise_match(left, right, left_col, right_col, threshold=0.6):
	"""Return DataFrame of matched rows between left and right based on text similarity.

	Uses difflib.SequenceMatcher for a quick similarity score. Returns merged frame
	with suffixes and a 'score' column.
	"""
	from difflib import SequenceMatcher
	left = left.copy()
	right = right.copy()
	left['_txt'] = left[left_col].fillna("").astype(str)
	right['_txt'] = right[right_col].fillna("").astype(str)

	matches = []
	# For efficiency limit to reasonable sizes
	max_left = min(len(left), 500)
	max_right = min(len(right), 500)
	for i, lrow in left.head(max_left).iterrows():
		best_j = None
		best_score = 0.0
		for j, rrow in right.head(max_right).iterrows():
			s = SequenceMatcher(None, lrow['_txt'], rrow['_txt']).ratio()
			if s > best_score:
				best_score = s
				best_j = j
		if best_score >= threshold and best_j is not None:
			merged = pd.concat([lrow.to_frame().T.reset_index(drop=True), right.loc[best_j].to_frame().T.reset_index(drop=True)], axis=1)
			merged['score'] = best_score
			matches.append(merged)
	if not matches:
		return pd.DataFrame()
	return pd.concat(matches, ignore_index=True)


def fuzzy_three_way_attach_datasets(incidents, tickets, datasets):
	"""Run fuzzy match between incidents.description and tickets.description,
	then attempt to attach dataset rows where dataset name appears in the merged description.
	Returns merged frame and a message."""
	if 'description' not in incidents.columns or 'description' not in tickets.columns:
		return pd.DataFrame(), 'Missing description columns for fuzzy match'
	m = fuzzy_pairwise_match(incidents, tickets, 'description', 'description', threshold=0.45)
	if m.empty:
		return pd.DataFrame(), 'No fuzzy matches found between incidents and tickets'
	# Try to attach datasets by looking for dataset name substring in combined description
	if 'name' not in datasets.columns:
		return m, 'Matched incidents↔tickets but datasets lack name column to attach'
	m['_combined_desc'] = m.apply(lambda r: ' '.join([str(r.get('description_x','')), str(r.get('description_y',''))]), axis=1)
	attached = []
	for idx, row in m.iterrows():
		found = None
		for _, drow in datasets.iterrows():
			if str(drow.get('name','')).lower() in row['_combined_desc'].lower():
				found = drow
				break
		if found is not None:
			merged = pd.concat([row.to_frame().T.reset_index(drop=True), found.to_frame().T.reset_index(drop=True)], axis=1)
			attached.append(merged)
	if not attached:
		return m, 'Matched incidents↔tickets but no dataset name substring matches found'
	return pd.concat(attached, ignore_index=True), 'Fuzzy attach succeeded'


def run_app():
	# Try to set a friendly page title — if an entrypoint already set page config
	# this will raise, so ignore errors.
	try:
		st.set_page_config(page_title="Secure Login", page_icon="🏠", layout="wide")
	except Exception:
		pass
	# Only show the marketing/landing content when NOT logged in
	if not is_logged_in():
		st.markdown("## Welcome")
		st.title("Multi-Domain Intelligence Platform")
		st.subheader("What you can do:")
		st.markdown(
			"- 🔐  Secure login and admin-managed password resets  \n"
			"- 📊  View enhanced dashboards for Cyber, Datasets and IT Tickets  \n"
			"- 🧩  Advanced integration heuristics (exact join, fuzzy match, nearest-timestamp)  \n"
			"- ⬇️  Export merged results to CSV"
		)

	df_cyber = load_csv("cyber_incidents.csv")
	df_datasets = load_csv("datasets_metadata.csv")
	# Ensure admin exists
	try:
		ensure_admin()
	except Exception:
		pass
	df_tickets = load_csv("it_tickets.csv")

	sidebar = st.sidebar
	sidebar.header("Navigation")

	# If user is not authenticated show the specifications on the main page
	# and put Login / Register / Admin Reset controls into the sidebar.
	if not is_logged_in():

		# Sidebar auth controls
		auth_choice = sidebar.radio("Authentication", ["Login", "Register", "Admin Reset"]) if sidebar else "Login"

		if auth_choice == "Login":
			su = sidebar.text_input("Username", key="sidebar_login_user")
			sp = sidebar.text_input("Password", type="password", key="sidebar_login_pwd")
			if sidebar.button("Login", key="sidebar_login_btn"):
				if not su or not sp:
					st.sidebar.error("Provide username and password")
				else:
					user = get_user_by_username(su)
					if not user:
						st.sidebar.error("Unknown user")
					else:
						_, _, hashed = user
						try:
							if verify_password(sp, hashed):
								login_user(su)
								# After successful login, default to Overview and rerun
								st.session_state['page'] = 'Overview'
								try:
									st.rerun()
								except Exception:
									st.success("Login successful — please refresh the page")
							else:
								st.sidebar.error("Invalid credentials")
						except Exception:
							st.sidebar.error("Authentication failed")

		elif auth_choice == "Register":
			r_user = sidebar.text_input("Choose username", key="sidebar_reg_user")
			r_pwd = sidebar.text_input("Choose password", type="password", key="sidebar_reg_pwd")
			r_confirm = sidebar.text_input("Confirm password", type="password", key="sidebar_reg_confirm")
			if sidebar.button("Create account", key="sidebar_reg_btn"):
				if not r_user or not r_pwd:
					st.sidebar.error("Username and password required")
				elif r_pwd != r_confirm:
					st.sidebar.error("Passwords do not match")
				else:
					import re
					policy = [
						(lambda s: len(s) >= 6, "at least 6 characters"),
						(lambda s: re.search(r"[A-Z]", s), "an uppercase letter"),
						(lambda s: re.search(r"[a-z]", s), "a lowercase letter"),
						(lambda s: re.search(r"[0-9]", s), "a number"),
						(lambda s: re.search(r"[^A-Za-z0-9]", s), "a special character"),
					]
					failed = [msg for fn, msg in policy if not fn(r_pwd)]
					if failed:
						st.sidebar.error("Password must contain: " + ", ".join(failed))
					else:
						try:
							existing = get_user_by_username(r_user)
							if existing:
								st.sidebar.error("Username already exists")
							else:
								register_user(r_user, r_pwd)
								st.sidebar.success("Registered — you may now log in")
						except Exception as e:
							st.sidebar.error(f"Registration failed: {e}")

		else:  # Admin Reset
			ar_user = sidebar.text_input("Username to reset", key="sidebar_fp_user")
			ar_new = sidebar.text_input("New password", type="password", key="sidebar_fp_new")
			ar_itid = sidebar.text_input("Admin IT ID", key="sidebar_fp_itid")
			if sidebar.button("Reset password (Admin)", key="sidebar_fp_reset_btn"):
				if not ar_user or not ar_new or not ar_itid:
					st.sidebar.error("Provide username, new password and admin IT ID")
				elif ar_itid != ADMIN_IT_ID:
					st.sidebar.error("Invalid admin IT ID")
				else:
					try:
						ok = reset_user_password(ar_user, ar_new)
						if ok:
							st.sidebar.success(f"Password for {ar_user} reset successfully")
						else:
							st.sidebar.warning(f"No such user: {ar_user}")
					except Exception as e:
						st.sidebar.error(f"Reset failed: {e}")

		# keep the main page showing the specifications only
		return

	# When logged in, present Dashboard option
	if is_logged_in():
		page = sidebar.radio("📍 Navigation", ["Home", "Dashboard"], index=0)
		sidebar.divider()
	else:
		page = None
	
	# show active users count in sidebar for everyone and admin-only list
	try:
		users_list = get_active_users()
		au_count = len(users_list)
	except Exception:
		users_list = []
		au_count = 0
	
	current_user = st.session_state.get('user')
	
	# admin-only expanded view of who's active
	if current_user == ADMIN_USERNAME:
		with sidebar.expander("👥 Active Users (Admin)"):
			sidebar.markdown(f"**Count:** {au_count}")
			if users_list:
				for u in users_list:
					st.write(f"- {u}")
			else:
				st.write("No active users")
	else:
		sidebar.markdown(f"**👥 Active users:** {au_count}")

	sidebar.divider()
	if st.sidebar.button("🚪 Logout", type="secondary", use_container_width=True):
		from session_time import logout_user
		logout_user()
		# clear page selection and rerun to show login
		st.session_state.pop('page', None)
		try:
			st.rerun()
		except Exception:
			return

	if page == "Home":
		# Home page: welcome and usage guide
		st.markdown("# Welcome to Multi-Domain Intelligence Platform")
		st.markdown("""
		## 📊 About This Platform
		
		This platform provides integrated intelligence across three key domains:
		- **🔐 Cyber Incidents** — Track and analyze security events
		- **📂 Datasets** — Explore metadata and dataset records
		- **🎫 IT Tickets** — Monitor and manage IT operations
		
		## 🚀 How to Use
		
		1. **Dashboard** — Navigate to the Dashboard to explore all three domains
		2. **Overview Tab** — See visual analytics and summary metrics
		3. **Incidents Tab** — Browse detailed data tables for each domain
		4. **Cross Link Tab** — Perform advanced cross-domain integration and merging
		5. **Export** — Download merged results as CSV files
		
		## 🔧 Key Features
		
		- **Multi-Heuristic Integration** — Exact joins, fuzzy matching, timestamp-based merging
		- **Interactive Charts** — Bar charts, pie charts, and detailed visualizations
		- **CSV Export** — Download integration results for external analysis
		- **Admin Controls** — Manage users and view active sessions
		
		## 👤 Getting Started
		
		Select **Dashboard** from the navigation menu to begin exploring the data.
		""")

	elif page == "Dashboard":
		# Dashboard with three tabs: Overview, Incidents, Cross Link
		dashboard_tab = st.radio("📑 Dashboard Tabs", ["Overview", "Incidents", "Cross Link"], 
		                         horizontal=True, label_visibility="collapsed")

		if dashboard_tab == "Overview":
		    # Overview: infographics with pie charts, graphs, and metrics
		    st.markdown("### Visual Analytics Across All Domains")
			
		    # Top metrics row
		    c1, c2, c3 = st.columns(3)
		    c1.metric("🔐 Cyber Incidents", str(len(df_cyber)))
		    c2.metric("📂 Datasets", str(len(df_datasets)))
		    c3.metric("🎫 IT Tickets", str(len(df_tickets)))

		    st.divider()

		    # Cyber visuals
		    col1, col2 = st.columns(2)
		    with col1:
		        st.subheader("Cyber Incidents")
		        if not df_cyber.empty:
		            candidates = [c for c in ["severity", "incident_type", "type", "category"] if c in df_cyber.columns]
		            if candidates:
		                col = candidates[0]
		                counts = df_cyber[col].fillna("(unknown)").astype(str).value_counts()
		                fig = px.bar(x=counts.index, y=counts.values, labels={'x': col, 'y': 'Count'}, 
		                            title=f"Cyber by {col.title()}", color=counts.values, color_continuous_scale='Reds')
		                st.plotly_chart(fig, use_container_width=True)
		            else:
		                st.info("No categorical column found in Cyber for breakdown")
		        else:
		            st.info("No Cyber data available")

		    with col2:
		        st.subheader("IT Tickets")
		        if not df_tickets.empty:
		            t_cands = [c for c in ["priority", "status", "state"] if c in df_tickets.columns]
		            if t_cands:
		                tcol = t_cands[0]
		                tcounts = df_tickets[tcol].fillna("(unknown)").astype(str).value_counts()
		                fig2 = px.pie(values=tcounts.values, names=tcounts.index, title=f"Tickets by {tcol.title()}",
		                             hole=0.3, color_discrete_sequence=px.colors.sequential.Blues_r)
		                st.plotly_chart(fig2, use_container_width=True)
		            else:
		                st.info("No ticket categorical column found")
		        else:
		            st.info("No Tickets data available")

		    st.divider()

		    # Datasets visuals (full width)
		    st.subheader("Datasets Metadata")
		    if not df_datasets.empty:
		        d_cands = [c for c in ["dataset_name", "name", "title"] if c in df_datasets.columns]
		        if d_cands:
		            dcol = d_cands[0]
		            dcounts = df_datasets[dcol].fillna("(unknown)").astype(str).value_counts().nlargest(10)
		            fig3 = px.bar(x=dcounts.index, y=dcounts.values, labels={'x': dcol.title(), 'y': 'Count'}, 
		                        title=f"Top {len(dcounts)} Datasets", color=dcounts.values, color_continuous_scale='Greens')
		            st.plotly_chart(fig3, use_container_width=True)
		        else:
		            st.metric("Total Datasets", str(len(df_datasets)))
		    else:
		        st.info("No Datasets data available")

		elif dashboard_tab == "Incidents":
			# Incidents: all data tables in one place
			st.markdown("### Detailed Records from All Three Domains")

			tab1, tab2, tab3 = st.tabs(["🔐 Cyber Incidents", "📂 Datasets Metadata", "🎫 IT Tickets"])

			with tab1:
				if df_cyber.empty:
					st.warning("No cyber incident records available (DB table empty and CSV missing).")
				else:
					st.write(f"**Total Records:** {len(df_cyber)}")
					st.dataframe(df_cyber, use_container_width=True)
					
					# Additional visuals
					if "severity" in df_cyber.columns:
						st.write("### Incidents by Severity")
						severity_counts = df_cyber["severity"].value_counts()
						fig = px.bar(x=severity_counts.index, y=severity_counts.values, 
						            labels={'x': 'Severity', 'y': 'Count'}, color=severity_counts.values,
						            color_continuous_scale='Reds')
						st.plotly_chart(fig, use_container_width=True)
					
					if "incident_type" in df_cyber.columns:
						fig = px.pie(df_cyber, names="incident_type", title="Incident Type Distribution", hole=0.3)
						st.plotly_chart(fig, use_container_width=True)

			with tab2:
				if df_datasets.empty:
					st.warning("No dataset metadata available (DB table empty and CSV missing).")
				else:
					st.write(f"**Total Datasets:** {len(df_datasets)}")
					st.dataframe(df_datasets, use_container_width=True)
					
					if "dataset_name" in df_datasets.columns and "records" in df_datasets.columns:
						fig_meta = px.bar(df_datasets, x="dataset_name", y="records", 
						                 title="Record Count per Dataset", color="records",
						                 color_continuous_scale='Greens')
						st.plotly_chart(fig_meta, use_container_width=True)

			with tab3:
				if df_tickets.empty:
					st.warning("No IT ticket records available (DB table empty and CSV missing).")
				else:
					st.write(f"**Total Tickets:** {len(df_tickets)}")
					st.dataframe(df_tickets, use_container_width=True)
					
					if "priority" in df_tickets.columns:
						st.write("### Tickets by Priority")
						priority_counts = df_tickets["priority"].value_counts()
						fig_t = px.bar(x=priority_counts.index, y=priority_counts.values, 
						              labels={'x': 'Priority', 'y': 'Count'}, 
						              title="Priority Distribution", color=priority_counts.values,
						              color_continuous_scale='Blues')
						st.plotly_chart(fig_t, use_container_width=True)

		elif dashboard_tab == "Cross Link":
			# Cross Link: advanced integration with all heuristics
			st.markdown("### Advanced Integration & Cross-Linking")
			st.markdown("Merge and cross-link data from multiple domains using intelligent heuristics")
			
			if df_cyber.empty and df_datasets.empty and df_tickets.empty:
				st.warning("⚠️ No domain CSVs found in DATA/ or DOCS/. Place `cyber_incidents.csv`, `datasets_metadata.csv`, and `it_tickets.csv`.")
			else:
				st.markdown("---")
				st.subheader("Select Integration Method")
				heuristic = st.selectbox("Choose a heuristic:", [
					"Exact common-key join",
					"Description substring match", 
					"Nearest timestamp (days)",
					"Auto cross-link (three-way)",
					"Fuzzy incidents↔tickets",
					"Fuzzy three-way (attach datasets)",
					"Manual three-way cross-link"
				])
				
				if heuristic == "Exact common-key join":
					st.markdown("**Method:** Join all three domains on a single shared column")
					common_cd = set(df_cyber.columns) & set(df_datasets.columns)
					common_all = common_cd & set(df_tickets.columns)
					st.write("Common columns across all domains:", list(common_all) if common_all else "None found")
					key = st.selectbox("Join key to use (exact)", options=[None] + list(common_all))
					if key and st.button("🔗 Run exact join", type="primary"):
						merged = pd.merge(df_cyber, df_datasets, on=key, how=cast(Any, 'inner'))
						merged = pd.merge(merged, df_tickets, on=key, how=cast(Any, 'inner'))
						st.success(f"✅ Exact join produced {len(merged)} rows")
						st.dataframe(merged.head(50), use_container_width=True)
						download_df(merged, filename='crosslink_exact_join.csv')
				
				elif heuristic == "Description substring match":
					st.markdown("**Method:** Fuzzy matching based on text similarity between descriptions")
					left_col = st.selectbox("Cyber text column", options=[None] + list(df_cyber.columns))
					right_col = st.selectbox("Tickets text column", options=[None] + list(df_tickets.columns))
					if st.button("🔗 Run fuzzy description match", type="primary"):
						if not left_col or not right_col:
							st.error("❌ Select text columns from both tables")
						else:
							merged = fuzzy_description_merge(df_cyber, df_tickets, left_col, right_col)
							st.success(f"✅ Fuzzy description match returned {len(merged)} rows")
							st.dataframe(merged.head(50), use_container_width=True)
							download_df(merged, filename='crosslink_fuzzy_desc.csv')
				
				elif heuristic == "Nearest timestamp (days)":
					st.markdown("**Method:** Join records within a time window")
					left_ts = st.selectbox("Cyber timestamp column", options=[None] + list(df_cyber.columns))
					right_ts = st.selectbox("Tickets timestamp column", options=[None] + list(df_tickets.columns))
					tol = st.number_input("Tolerance (days)", min_value=0, max_value=365, value=1)
					if st.button("🔗 Run nearest-timestamp merge", type="primary"):
						if not left_ts or not right_ts:
							st.error("❌ Select timestamp columns from both tables")
						else:
							merged = nearest_timestamp_merge(df_cyber, df_tickets, left_ts, right_ts, tolerance_days=tol)
							st.success(f"✅ Nearest timestamp merge returned {len(merged)} rows")
							st.dataframe(merged.head(50), use_container_width=True)
							download_df(merged, filename='crosslink_nearest_ts.csv')
				
				elif heuristic == "Auto cross-link (three-way)":
					st.markdown("**Method:** Automatically try all heuristics and report which succeeded")
					if st.button("🤖 Run auto cross-link", type="primary"):
						with st.spinner("Attempting automated three-way cross-link using multiple heuristics..."):
							merged_all, info = crosslink_three_way(df_cyber, df_datasets, df_tickets)
						if merged_all.empty:
							st.warning(f"⚠️ {info}")
						else:
							st.success(f"✅ Cross-link succeeded ({info}) — {len(merged_all)} rows")
							st.dataframe(merged_all.head(200), use_container_width=True)
							download_df(merged_all, filename='crosslink_auto.csv')
				
				elif heuristic == "Fuzzy incidents↔tickets":
					st.markdown("**Method:** Text-similarity-based matching between incidents and tickets")
					if 'description' not in df_cyber.columns or 'description' not in df_tickets.columns:
						st.error('❌ Both tables must have a description column for fuzzy matching')
					else:
						thr = st.slider('Similarity threshold', 0.0, 1.0, 0.6, help="Higher values = stricter matching")
						if st.button('🔗 Run fuzzy pairwise match', type="primary"):
							with st.spinner("Running fuzzy matching..."):
								res = fuzzy_pairwise_match(df_cyber, df_tickets, 'description', 'description', threshold=thr)
							if res.empty:
								st.warning('⚠️ No fuzzy matches found at this threshold')
							else:
								st.success(f'✅ Found {len(res)} fuzzy matches')
								st.dataframe(res.head(200), use_container_width=True)
								download_df(res, filename='crosslink_fuzzy_pairwise.csv')
				
				elif heuristic == "Fuzzy three-way (attach datasets)":
					st.markdown("**Method:** Fuzzy match incidents↔tickets, then attach datasets by name substring")
					if st.button('🔗 Run fuzzy three-way attach', type="primary"):
						with st.spinner("Running fuzzy three-way attach..."):
							merged3, info = fuzzy_three_way_attach_datasets(df_cyber, df_tickets, df_datasets)
						if merged3.empty:
							st.warning(f"⚠️ {info}")
						else:
							st.success(f"✅ {info} — produced {len(merged3)} rows")
							st.dataframe(merged3.head(200), use_container_width=True)
							download_df(merged3, filename='crosslink_fuzzy_three_way.csv')
				
				elif heuristic == "Manual three-way cross-link":
					st.markdown("**Method:** Manually select columns from each domain to join")
					with st.expander("📋 View Data Schemas"):
						st.write("**Cyber columns:**", list(df_cyber.columns))
						st.write("**Datasets columns:**", list(df_datasets.columns))
						st.write("**Tickets columns:**", list(df_tickets.columns))
						st.write(f"**Rows** — Cyber: {len(df_cyber)}, Datasets: {len(df_datasets)}, Tickets: {len(df_tickets)}")

					col_a = st.selectbox("Cyber column to join", options=[None] + list(df_cyber.columns))
					col_b = st.selectbox("Datasets column to join", options=[None] + list(df_datasets.columns))
					col_c = st.selectbox("Tickets column to join (for final join)", options=[None] + list(df_tickets.columns))
					if st.button("🔗 Run manual three-way join", type="primary"):
						if not col_a or not col_b or not col_c:
							st.error("❌ Select a column from each table to perform the manual join")
						else:
							try:
								m12 = pd.merge(df_cyber, df_datasets, left_on=col_a, right_on=col_b, how='inner')
								m123 = pd.merge(m12, df_tickets, left_on=col_b, right_on=col_c, how='inner')
								if m123.empty:
									st.warning("⚠️ Manual join produced no rows — try different column choices or inspect the schema")
								else:
									st.success(f"✅ Manual cross-link produced {len(m123)} rows")
									st.dataframe(m123.head(200), use_container_width=True)
									download_df(m123, filename='crosslink_manual.csv')
							except Exception as e:
								st.error(f"❌ Manual cross-link failed: {e}")


if __name__ == "__main__":
	run_app()