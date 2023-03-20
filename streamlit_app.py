import streamlit as st
import pandas as pd
from scapy.all import rdpcap
import requests

def pcap_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)
    packet_list = []
    for packet in packets:
        packet_dict = {}
        if 'IP' in packet:
            packet_dict['Source IP'] = packet['IP'].src
            packet_dict['Destination IP'] = packet['IP'].dst
        if 'TCP' in packet:
            packet_dict['Source Port (TCP)'] = packet['TCP'].sport
            packet_dict['Destination Port (TCP)'] = packet['TCP'].dport
        packet_list.append(packet_dict)
    df = pd.DataFrame(packet_list)
    return df

def get_public_ips(df):
    public_ips = []
    for ip in df['Source IP'].unique():
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json')
            data = response.json()
            if 'bogon' in data:
                continue
            if 'private' in data['ip']:
                continue
            public_ips.append(ip)
        except:
            continue
    return public_ips

def get_virustotal_results(api_key, ip):
    headers = {'x-apikey': api_key}
    params = {'ip': ip}
    response = requests.get('https://www.virustotal.com/api/v3/ip_addresses',
                            headers=headers,
                            params=params)
    data = response.json()
    return data

def main():
    st.title("PCAP Viewer")

    st.sidebar.header("Options")
    pcap_file = st.sidebar.file_uploader("Upload a PCAP file")
    if not pcap_file:
        st.sidebar.info("Please upload a PCAP file")
        st.stop()
    sort_by = st.sidebar.selectbox("Sort by", ["Source Port (TCP)", "Destination Port (TCP)"])

    st.sidebar.subheader("Public IP Addresses")
    df = pcap_to_dataframe(pcap_file)
    public_ips = get_public_ips(df)
    selected_ips = st.sidebar.multiselect("Select IP addresses to scan with VirusTotal", public_ips)

    api_key = st.sidebar.text_input("Enter your VirusTotal API key")

    st.sidebar.subheader("Actions")
    if st.sidebar.button("Scan selected IPs with VirusTotal"):
        for ip in selected_ips:
            data = get_virustotal_results(api_key, ip)
            st.write(f"Results for {ip}:")
            st.write(data)
            st.write("---")

    st.subheader("RAW data")
    st.write(df)
    st.subheader("Sorted data")
    if sort_by == "Source Port (TCP)":
        sorted_df = df.sort_values("Source Port (TCP)")
    elif sort_by == "Destination Port (TCP)":
        sorted_df = df.sort_values("Destination Port (TCP)")
    st.write(sorted_df)

if __name__ == "__main__":
    main()
