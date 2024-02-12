import streamlit as st
import pandas as pd
import numpy as np
import pickle

# load all files

with open("model.pkl", "rb") as f: # load the model
    model = pickle.load(f)
    
with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open("encoder.pkl", "rb") as f: # load the scaler
    encoder = pickle.load(f)

with open('column_names.pkl', 'rb') as f:
    column_names = pickle.load(f)

def app():
    
    with st.form('from_website_data'):
        # write short description about the model
        st.write('''
        # **Malicious or Benign Website Detection**
        - The model used for this detection is `XGBoost` Classifier which Hyperparameter have been tuned.
        - The model also used `SMOTENC` to handle imbalanced data during training.
        - This model achieved `0.93` recall score on the test set to detect malicious website.
        ''')
        
        url = st.text_input('URL', 'https://www.google.com', help='The URL that will be analyzed')

        URL_LENGTH = len(url)

        NUMBER_SPECIAL_CHARACTERS = sum(not x.isalnum() for x in url)

        charset_choice = {1: "ISO-8859-1", 2: "UTF-8", 3: "utf-8", 4: "us-ascii", 5: "iso-8859-1", 6: "unknown", 7: "windows-1252", 8: "windows-1251"}
                
        server_choice = {1: 'Apache', 2: 'cloudflare-nginx', 3: 'other', 4: 'Server', 5: 'GSE', 6: 'nginx', 7: 'unknown', 8: 'Microsoft-HTTPAPI/2.0', 9: 'nginx/1.8.0', 10: 'nginx/1.10.1', 11: 'Microsoft-IIS/7.5', 12: 'YouTubeFrontEnd', 13: 'Apache/2.2.22 (Debian)', 14: 'nginx/1.12.0', 15: 'Microsoft-IIS/6.0', 16: 'Apache/2.4.23 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4', 17: 'Apache/2.2.14 (FreeBSD) mod_ssl/2.2.14 OpenSSL/0.9.8y DAV/2 PHP/5.2.12 with Suhosin-Patch'}
        
        whois_country_choice = {1: "AU", 2: "CA", 3: "ES", 4: "US", 5: "other", 6: "unknown", 7: "PA", 8: "FR", 9: "KR", 10: "CZ", 11: "JP", 12: "ru", 13: "UK", 14: "CN", 15: "GB", 16: "UY"}
                
        WHOIS_STATEPRO_choice = {1: "other", 2: "Barcelona", 3: "CA", 4: "NV", 5: "Washington", 6: "unknown", 7: "Arizona", 8: "UT", 9: "NY", 10: "ON", 11: "PA", 12: "FL", 13: "California", 14: "PRAHA", 15: "WA", 16: "Krasnoyarsk", 17: "Utah", 18: "WC1N"}

        CHARSET = st.selectbox("Select Charset", options=list(charset_choice.values()), help='The character encoding standard (also called character set)')

        SERVER = st.selectbox("Select Server", options=list(server_choice.values()), help='The operative system of the server got from the packet response')

        CONTENT_LENGTH = st.number_input('CONTENT_LENGTH', min_value=0, max_value=9806, value=50, help='The content size of the HTTP header')

        WHOIS_COUNTRY = st.selectbox("Select Country", options=list(whois_country_choice.values()), help='The countries we got from the server response (specifically, our script used the API of Whois)')

        WHOIS_STATEPRO = st.selectbox("Select States", options=list(WHOIS_STATEPRO_choice.values()), help='The states we got from the server response (specifically, our script used the API of Whois)')

        WHOIS_REGDATE = st.date_input('WHOIS_REGDATE', help='Whois provides the server registration date')

        WHOIS_UPDATED_DATE = st.date_input('WHOIS_UPDATED_DATE', help='Through the Whois we got the last update date from the server analyzed')
        
        TCP_CONVERSATION_EXCHANGE = st.number_input('TCP_CONVERSATION_EXCHANGE', min_value=0, max_value=84, value=50, help='This variable is the number of TCP packets exchanged between the server and our honeypot client')

        DIST_REMOTE_TCP_PORT = st.number_input('DIST_REMOTE_TCP_PORT', min_value=0, max_value=20, value=0, help='It is the number of the ports detected and different to TCP')

        REMOTE_IPS = st.number_input('REMOTE_IPS', min_value=0, max_value=16, value=0, help='This variable has the total number of IPs connected to the honeypot')

        APP_BYTES = st.number_input('APP_BYTES', min_value=0, max_value=9302, value=50, help='This is the number of bytes transferred')

        REMOTE_APP_BYTES = st.number_input('REMOTE_APP_BYTES', min_value=0, max_value=100000, value=0, help='This is the number of bytes received from the server')

        SOURCE_APP_BYTES = st.number_input('SOURCE_APP_BYTES', min_value=0, max_value=100000, value=0, help='This is the number of bytes sent to the server')

        SOURCE_APP_PACKETS = st.number_input('SOURCE_APP_PACKETS', min_value=0, max_value=103, value=50, help='Packets sent from the honeypot to the server')

        REMOTE_APP_PACKETS = st.number_input('REMOTE_APP_PACKETS', min_value=0, max_value=99, value=50, help='Packets received from the server')

        APP_PACKETS = st.number_input('APP_PACKETS', min_value=0, max_value=103, value=50, help='This is the total number of IP packets generated during the communication between the honeypot and the server')

        DNS_QUERY_TIMES = st.number_input('DNS_QUERY_TIMES', min_value=0, max_value=20, value=0, help='This is the number of DNS packets generated during the communication between the honeypot and the server')
        
        #submit buttion
        submitted = st.form_submit_button('Predict')
    
    data_inf = {
        'URL_LENGTH': URL_LENGTH,
        'NUMBER_SPECIAL_CHARACTERS': NUMBER_SPECIAL_CHARACTERS,
        'CONTENT_LENGTH': CONTENT_LENGTH,
        'WHOIS_REGDATE': WHOIS_REGDATE,
        'WHOIS_UPDATED_DATE': WHOIS_UPDATED_DATE,
        'TCP_CONVERSATION_EXCHANGE': TCP_CONVERSATION_EXCHANGE,
        'DIST_REMOTE_TCP_PORT': DIST_REMOTE_TCP_PORT,
        'REMOTE_IPS': REMOTE_IPS,
        'APP_BYTES': APP_BYTES,
        'SOURCE_APP_PACKETS': SOURCE_APP_PACKETS,
        'REMOTE_APP_PACKETS': REMOTE_APP_PACKETS,
        'SOURCE_APP_BYTES': SOURCE_APP_BYTES,
        'REMOTE_APP_BYTES': REMOTE_APP_BYTES,
        'APP_PACKETS': APP_PACKETS,
        'DNS_QUERY_TIMES': DNS_QUERY_TIMES,
        'CHARSET': CHARSET,
        'SERVER': SERVER,
        'WHOIS_COUNTRY': WHOIS_COUNTRY,
        'WHOIS_STATEPRO': WHOIS_STATEPRO
    }

    
    
    data_inf = pd.DataFrame([data_inf])
    # st.dataframe(data_inf)

    def encode_and_create_dataframe_train(df, column):
        # Fit a separate OneHotEncoder for the column
        transformed_data = encoder.fit_transform(df[[column]])

        # Get feature names for the column
        feature_names = encoder.get_feature_names_out(input_features=[column])

        # Create a DataFrame for the column
        transformed_df = pd.DataFrame(transformed_data.toarray(), 
                                    index=df.index, 
                                    columns=feature_names)
    
        return transformed_df, encoder

    # logic ketika user submit
    if submitted:
        #split between numerical and categorical columns
        data_inf_num = data_inf[['URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS', 'CONTENT_LENGTH', 
                                 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE', 'TCP_CONVERSATION_EXCHANGE', 
                                 'DIST_REMOTE_TCP_PORT', 'REMOTE_IPS', 'APP_BYTES', 'SOURCE_APP_PACKETS', 
                                 'REMOTE_APP_PACKETS', 'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES', 'APP_PACKETS', 
                                 'DNS_QUERY_TIMES']]
        data_inf_cat = data_inf[['CHARSET', 'SERVER', 'WHOIS_COUNTRY', 'WHOIS_STATEPRO']]
                
        # Convert to datetime format
        data_inf_num['WHOIS_REGDATE'] = pd.to_datetime(data_inf_num['WHOIS_REGDATE'])
        data_inf_num['WHOIS_UPDATED_DATE'] = pd.to_datetime(data_inf_num['WHOIS_UPDATED_DATE'])

        # Extract year as integer
        data_inf_num['WHOIS_REGDATE'] = data_inf_num['WHOIS_REGDATE'].dt.year
        data_inf_num['WHOIS_UPDATED_DATE'] = data_inf_num['WHOIS_UPDATED_DATE'].dt.year
        
        # scaling and encoding
        data_inf_num_scaled = scaler.transform(data_inf_num)
        
        # transform to dataframe
        data_inf_num_scaled = pd.DataFrame(data_inf_num_scaled, columns=data_inf_num.columns)

        capped_CHARSET, ohe_CHARSET = encode_and_create_dataframe_train(data_inf_cat, 'CHARSET')
        capped_SERVER, ohe_SERVER = encode_and_create_dataframe_train(data_inf_cat, 'SERVER')
        capped_WHOIS_COUNTRY, ohe_WHOIS_COUNTRY = encode_and_create_dataframe_train(data_inf_cat, 'WHOIS_COUNTRY')
        capped_WHOIS_STATEPRO, ohe_WHOIS_STATEPRO = encode_and_create_dataframe_train(data_inf_cat, 'WHOIS_STATEPRO')
        
        # concat all data 
        data_inf_final = pd.concat([data_inf_num_scaled, capped_CHARSET, capped_SERVER, capped_WHOIS_COUNTRY, capped_WHOIS_STATEPRO], axis=1)
        
        if len(column_names) != len(set(column_names)):
            st.write("column_names contains duplicates")
            
        if len(data_inf_final.columns) != len(set(data_inf_final.columns)):
            st.write("data_inf_final has duplicate column names")
                
        # reindex to match the training columns
        data_inf_final = data_inf_final.reindex(columns=column_names)

        # Check Missing Values
        data_inf_final.isnull().sum()

        # fill null value with zeros
        data_inf_final = data_inf_final.fillna(0)
        
        #predict using linear reg model

        y_pred_inf = model.predict(data_inf_final)
        
        st.dataframe(data_inf)
        
        if y_pred_inf == 0:
            # write with green color
            st.markdown("<h1 style='text-align: center; color: green;'>Predicted Class: Benign</h1>", unsafe_allow_html=True)        
        else:
            st.markdown("<h1 style='text-align: center; color: red;'>Predicted Class: Malicious</h1>", unsafe_allow_html=True)                
        
        
if __name__ == '__main__':
    app()