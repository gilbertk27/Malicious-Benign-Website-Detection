import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
from PIL import Image

def app():
    # title
    st.title('Malicious or Benign Website Detection')

    # subheader
    st.subheader('EDA for Malicious or Benign Website Detection')

    # add image
    image = Image.open('web.jpg')
    st.image(image, caption = 'Malicious or Benign Website')

    # Markdown
    st.markdown('----')

    # Masukkan pandas dataframe

    # show dataframe
    df = pd.read_csv('dataset.csv')
    st.dataframe(df)
    
    # **Explanation directly taken from the website:**
    
    # writing dataset explanation
    st.write('#### Dataset Explanation')
    st.write('''
    - **URL**: It is the anonymous identification of the URL analyzed in the study.
    - **URL_LENGTH**: It is the number of characters in the URL.
    - **NUMBER_SPECIAL_CHARACTERS**: It is the number of special characters identified in the URL, such as, “/”, “%”, “#”, “&”, “. “, “=”.
    - **CHARSET**: It is a categorical value and its meaning is the character encoding standard (also called character set).
    - **SERVER**: It is a categorical value and its meaning is the operative system of the server got from the packet response.
    - **CONTENT_LENGTH**: It represents the content size of the HTTP header.
    - **WHOIS_COUNTRY**: It is a categorical variable, its values are the countries we got from the server response (specifically, our script used the API of Whois).
    - **WHOIS_STATEPRO**: It is a categorical variable, its values are the states we got from the server response (specifically, our script used the API of Whois).
    - **WHOIS_REGDATE**: Whois provides the server registration date, so, this variable has date values with format DD/MM/YYY HH:MM
    - **WHOIS_UPDATED_DATE**: Through the Whois we got the last update date from the server analyzed.
    - **TCP_CONVERSATION_EXCHANGE**: This variable is the number of TCP packets exchanged between the server and our honeypot client.
    - **DIST_REMOTE_TCP_PORT**: It is the number of the ports detected and different to TCP.
    - **REMOTE_IPS**: This variable has the total number of IPs connected to the honeypot.
    - **APP_BYTES**: This is the number of bytes transferred.
    - **SOURCE_APP_PACKETS**: Packets sent from the honeypot to the server.
    - **REMOTE_APP_PACKETS**: Packets received from the server.
    - **APP_PACKETS**: This is the total number of IP packets generated during the communication between the honeypot and the server.
    - **DNS_QUERY_TIMES**: This is the number of DNS packets generated during the communication between the honeypot and the server.
    - **TYPE**: This is a categorical variable, its values represent the type of web page analyzed, specifically, 1 is for malicious websites and 0 is for benign websites.
    ''')
    
    object_columns = df.select_dtypes(include=['object']).columns
    numerical_columns = df.select_dtypes(exclude=['object']).columns

    st.write('#### Plot Categorical Columns using Pie Chart')
    option_cat = st.selectbox('Select Column:', ('CHARSET', 'SERVER', 'WHOIS_COUNTRY', 'WHOIS_STATEPRO'))
    fig = plt.figure(figsize=(15,5))
    plt.pie(df[option_cat].value_counts(), labels=df[option_cat].value_counts().index, autopct='%1.1f%%', startangle=180)
    st.pyplot(fig)
    
    # # plot historical date data with lineplot for WHOIS_REGDATE and WHOIS_UPDATED_DATE separated by type column
    # date_columns = ['WHOIS_REGDATE', 'WHOIS_UPDATED_DATE']
    # st.write('#### Plot Historical Date Data with Lineplot')
    # option_date = st.selectbox('Select Column:', ('WHOIS_REGDATE', 'WHOIS_UPDATED_DATE'))
    # fig = plt.figure(figsize=(15,5))
    # sns.lineplot(x=option_date, y='Type', data=df)
    # st.pyplot(fig)
        
    st.write('#### Plot Numerical Columns')
    option = st.selectbox('Select Column:', ('URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS', 'CONTENT_LENGTH', 'APP_PACKETS', 'DNS_QUERY_TIMES'))
    fig = plt.figure(figsize=(15,5))
    sns.histplot(df[option], bins=30, kde=True)
    st.pyplot(fig)
    
    option_pay = st.selectbox('Select Column:', ('TCP_CONVERSATION_EXCHANGE', 'DIST_REMOTE_TCP_PORT', 'REMOTE_IPS', 'APP_BYTES'))
    fig = plt.figure(figsize=(15,5))
    sns.histplot(df[option_pay], bins=30, kde=True)
    st.pyplot(fig)
    
    option_bill_amt = st.selectbox('Select Column:', ('SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS', 'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES'))
    fig = plt.figure(figsize=(15,5))
    sns.histplot(df[option_bill_amt], bins=30, kde=True)
    st.pyplot(fig)

    # plot type column count with boxplot color with type column
    st.write('#### Plot Type Column Count with Boxplot')
    fig = plt.figure(figsize=(15,5))
    sns.boxplot(x='Type', y='URL_LENGTH', data=df, hue='Type')
    st.pyplot(fig)

    # Sort DataFrame by 'Type'
    df = df.sort_values('Type')

    # Membuat plotly plot
    st.write('#### Plotly Plot - URL_LENGTH vs CONTENT_LENGTH')
    fig  = plt.figure(figsize=(15,5))
    sns.scatterplot(x='URL_LENGTH', y='CONTENT_LENGTH', data=df, hue='Type')
    st.pyplot(fig)
    

if __name__ == '__main__':
    app()