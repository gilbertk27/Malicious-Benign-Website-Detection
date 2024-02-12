import streamlit as st
import eda
import prediction

page = st.sidebar.selectbox('Select Page: ', ('EDA', 'Prediction'))

if page == 'EDA':
    eda.app()
else:
    prediction.app()
    