import streamlit as st
import pandas as pd
import pickle
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="Log Anomaly Hunter", layout="wide")

st.title("🛡️ Log Anomaly Detection System")
st.markdown("Automated identification of security incidents using Isolation Forest.")

uploaded_file = st.file_uploader("Upload Log File (CSV)", type=["csv"])

# Если файл не загружен, используем сгенерированный по умолчанию для демо
if uploaded_file is None:
    st.info("Waiting for file upload. Using generated 'server_logs.csv' for demo purposes.")
    try:
        uploaded_file = "server_logs.csv"
    except:
        pass

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('encoders.pkl', 'rb') as f:
        le_method, le_url = pickle.load(f)

    try:
        df['method_code'] = le_method.transform(df['method'])
        df['url_code'] = le_url.transform(df['url'])
    except:
        df['method_code'] = 0
        df['url_code'] = 0

    features = ['status_code', 'response_size', 'method_code', 'url_code']
    
    df['anomaly_label'] = model.predict(df[features])
    df['is_anomaly'] = df['anomaly_label'].apply(lambda x: True if x == -1 else False)
    
    anomalies = df[df['is_anomaly'] == True]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Requests", len(df))
    col2.metric("Anomalies Detected", len(anomalies))
    col3.metric("Risk Level", "High" if len(anomalies) > 10 else "Low")

    st.divider()

    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Traffic Distribution")
        fig, ax = plt.subplots()
        df['status_code'].value_counts().plot(kind='bar', ax=ax, color='skyblue')
        st.pyplot(fig)
        
    with c2:
        st.subheader("Top Attacking IPs")
        if not anomalies.empty:
            fig2, ax2 = plt.subplots()
            anomalies['source_ip'].value_counts().head(5).plot(kind='barh', ax=ax2, color='red')
            st.pyplot(fig2)
        else:
            st.write("No anomalies found.")

    st.subheader("Detailed Anomaly Report")
    st.dataframe(anomalies[['timestamp', 'source_ip', 'method', 'url', 'status_code', 'user_agent']])
