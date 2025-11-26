import streamlit as st
import pandas as pd
 
df = pd.DataFrame({
    "region": ["North", "South", "East", "West"],
    "year": [2023, 2023, 2024, 2025],
    "revenue": [45000, 30000, 50000, 35000]
})
 
st.set_page_config(
    page_title='My app',
    page_icon='👋',
    layout='wide'
)
 
 
st.title("📊 Sales Dashboard")
with st.sidebar:
    st.header('Control')
    year = st.selectbox('Year', [2023, 2024, 2025])
    
 
filter = df[(df['year'] == year)]
 
col1, col2 = st.columns(2)
 
with col1:
    st.subheader('Left')
    st.bar_chart(filter)
 
with col2:
    st.subheader('Right')
    st.line_chart(filter)
 
 
with st.expander('See details'):
    st.write('Hidden content')
    st.dataframe(df)