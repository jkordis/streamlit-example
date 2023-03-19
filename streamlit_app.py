import streamlit as st
import pyshark
import pandas as pd
import requests
from ipaddress import ip_address, ip_network

def process_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    ip_list = []
    for pkt in capture:
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_public = False
            dst_public = False
            if ip_address(src_ip).is_private:
                src_public = False
            else:
                src_public = True
            if ip_address(dst_ip).is_private:
                dst_public = False
            else:
                dst_public = True
            ip_list.append((src_ip, dst_ip, src_public, dst_public))
        except AttributeError:
            pass
    capture.close()
    df = pd.DataFrame(ip_list, columns=["Source IP", "Destination IP", "Source Public", "Destination Public"])
    df = df.drop_duplicates()
    return df

def virustotal_lookup(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": "your_api_key_here"}
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

def main():
    st.title("IP Address Extractor and Virustotal Lookup")
    st.write("This app extracts all the found IP addresses from a pcap file and sorts them by public and private IP addresses.")
    st.write("You can then select addresses and run them against the virustotal api to get data for each.")
    st.write("Make sure to take the pcap and turn the object into a byte stream before passing it to pyshark.FileCapture")
    
    # Upload the pcap file
    file = st.file_uploader("Upload pcap file", type=["pcap", "pcapng"])
    if file is not None:
        df = process_pcap(file)
        st.write("## IP Addresses Found")
        st.write(df)
        
        # Select IP addresses to lookup in Virustotal
        selected_ips = st.multiselect("Select IP addresses to lookup in Virustotal", df["Source IP"])
        
        # Run Virustotal lookup for selected IPs
        if st.button("Lookup in Virustotal"):
            for ip in selected_ips:
                data = virustotal_lookup(ip)
                st.write(f"## {ip}")
                st.write(data)

if __name__ == "__main__":
    main()
