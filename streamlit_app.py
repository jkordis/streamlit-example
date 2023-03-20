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
    st.set_page_config(layout='wide')
    st.title("PCAP Analyzer")
    pcap_file = st.file_uploader("Upload a pcap file", type="pcap")

    if pcap_file is not None:
        df = pcap_to_dataframe(pcap_file)

        st.write("### Raw data")
        st.write(df)

        col1, col2 = st.beta_columns(2)
        with col1:
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

        with col2:
            public_ips = []
            for ip in df['Source IP'].unique():
                if not ipaddress.ip_address(ip).is_private:
                    public_ips.append(ip)
            for ip in df['Destination IP'].unique():
                if not ipaddress.ip_address(ip).is_private and ip not in public_ips:
                    public_ips.append(ip)
            public_ips = list(set(public_ips))

            public_df = pd.DataFrame(public_ips, columns=['Public IP'])
            public_df['Select'] = False
            public_df = public_df.drop_duplicates(subset='Public IP', keep=False)

            st.write("### Public IP addresses")
            selected_ips = st.multiselect("Select public IPs", options=public_df['Public IP'].tolist())
            public_df.loc[public_df['Public IP'].isin(selected_ips), 'Select'] = True
            public_df = public_df[['Public IP', 'Select']]
            st.write(public_df)

if __name__ == '__main__':
    main()
