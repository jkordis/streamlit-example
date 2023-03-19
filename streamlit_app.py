import streamlit as st
import pandas as pd
from scapy import all

def pcap_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)
    data = []
    for packet in packets:
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[IP].sport
            dport = packet[IP].dport
            data.append([src, dst, sport, dport])
        except:
            pass
    df = pd.DataFrame(data, columns=['Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    return df

def main():
    st.title("PCAP Analyzer")
    pcap_file = st.file_uploader("Upload a pcap file", type="pcap")

    if pcap_file is not None:
        df = pcap_to_dataframe(pcap_file)
        st.write(df)

        st.sidebar.title("Filter by:")
        ip_address = st.sidebar.selectbox("IP Address", options=['All'] + list(df['Source IP'].unique()))
        port = st.sidebar.selectbox("Port", options=['All'] + list(df['Source Port'].unique()))

        if ip_address != 'All':
            df = df[(df['Source IP'] == ip_address) | (df['Destination IP'] == ip_address)]
        if port != 'All':
            df = df[(df['Source Port'] == port) | (df['Destination Port'] == port)]

        st.write(df)

if __name__ == '__main__':
    main()
