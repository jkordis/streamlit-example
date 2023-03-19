import streamlit as st
import pandas as pd
from scapy.all import *
import ipaddress

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

        st.write("### Raw data")
        st.write(df)

        st.sidebar.title("Filter by:")
        ip_address = st.sidebar.selectbox("IP Address", options=['All'] + list(df['Source IP'].unique()))
        port = st.sidebar.selectbox("Port", options=['All'] + list(df['Source Port'].unique()))

        if ip_address != 'All':
            df = df[(df['Source IP'] == ip_address) | (df['Destination IP'] == ip_address)]
        if port != 'All':
            df = df[(df['Source Port'] == port) | (df['Destination Port'] == port)]

        st.sidebar.title("Sort by:")
        sort_by = st.sidebar.selectbox("Sort by", options=['None', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
        ascending = st.sidebar.checkbox("Ascending", value=True)

        if sort_by != 'None':
            df = df.sort_values(by=sort_by, ascending=ascending)

        st.write("### Filtered data")
        st.write(df)

        st.sidebar.title("Public IPs:")
        public_ips = []
        for ip in df['Source IP'].unique():
            if not ipaddress.ip_address(ip).is_private:
                public_ips.append(ip)
        for ip in df['Destination IP'].unique():
            if not ipaddress.ip_address(ip).is_private and ip not in public_ips:
                public_ips.append(ip)
        public_df = df[df['Source IP'].isin(public_ips) | df['Destination IP'].isin(public_ips)]
        st.write("### Public IP addresses")
        st.write(public_df)

if __name__ == '__main__':
    main()
