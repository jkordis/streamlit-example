import streamlit as st
from scapy.all import *
import pandas as pd
import requests


def pcap_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)
    packet_list = []
    for packet in packets:
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            packet_list.append((src, dst, sport, dport))
        except:
            pass
    df = pd.DataFrame(packet_list, columns=['Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    df.drop_duplicates(inplace=True)
    return df


def get_public_ip(ip):
    url = f'http://ipinfo.io/{ip}/json'
    response = requests.get(url)
    data = response.json()
    if 'bogon' in data:
        return None
    else:
        return data['ip']


def get_public_ips(df):
    public_ips = []
    for ip in df['Source IP'].unique():
        public_ip = get_public_ip(ip)
        if public_ip is not None:
            public_ips.append(public_ip)
    public_ip_df = pd.DataFrame(public_ips, columns=['Public IPs'])
    return public_ip_df


def main():
    st.title("PCAP Analysis Tool")
    st.sidebar.title("Settings")
    
    st.sidebar.subheader("Upload PCAP file")
    pcap_file = st.sidebar.file_uploader("Choose a file")
    
    st.sidebar.subheader("Sort table by")
    sort_by = st.sidebar.selectbox("", ["None", "Source IP", "Destination IP", "Source Port", "Destination Port"])
    
    st.sidebar.subheader("VirusTotal API key")
    vt_api_key = st.sidebar.text_input("Enter your VirusTotal API key", type="password")
    
    if pcap_file is not None:
        with st.spinner("Loading PCAP file..."):
            df = pcap_to_dataframe(pcap_file)
            public_ip_df = get_public_ips(df)
        
        if sort_by != "None":
            df = df.sort_values(by=[sort_by])
        
        st.write("RAW Data Table")
        st.write(df)
        
        st.write("Public IP Addresses Table")
        public_ip_df.drop_duplicates(inplace=True)
        public_ip_df.reset_index(drop=True, inplace=True)
        public_ip_df['Select'] = [False] * len(public_ip_df)
        public_ip_df = public_ip_df[['Select', 'Public IPs']]
        public_ip_df = public_ip_df[public_ip_df['Public IPs'].str.contains('\.')].reset_index(drop=True)
        public_ip_df = public_ip_df.groupby(['Public IPs']).first().reset_index()
        if public_ip_df.empty:
            st.write("No public IP addresses found.")
        else:
            selected_ips = st.multiselect("Select public IPs for VirusTotal scan", public_ip_df['Public IPs'])
            if st.button("Scan selected public IPs with VirusTotal") and vt_api_key != "":
                for ip in selected_ips:
                    url = f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={vt_api_key}&ip={ip}'
                    response = requests.get(url)
                    data = response.json()
                    st.write(f"Results for {ip}:")
                    st.write(data)
    else:
        st.warning("Please upload a PCAP file.")
    
if __name__ == '__main__':
    main()
