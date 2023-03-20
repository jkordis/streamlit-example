import streamlit as st
import pandas as pd
import requests
from scapy.all import *

# function to convert pcap to dataframe
def pcap_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)
    data = {
        "Source IP": [],
        "Destination IP": [],
        "Source Port (TCP)": [],
        "Destination Port (TCP)": []
    }
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                data["Source IP"].append(ip_src)
                data["Destination IP"].append(ip_dst)
                data["Source Port (TCP)"].append(tcp_sport)
                data["Destination Port (TCP)"].append(tcp_dport)
    df = pd.DataFrame(data)
    return df

# function to get public IP addresses
def get_public_ips(df):
    public_ips = set()
    for ip in df["Source IP"].unique():
        r = requests.get(f"http://ipinfo.io/{ip}/json")
        json = r.json()
        if "bogon" not in json and "private" not in json:
            public_ips.add(ip)
    return sorted(public_ips)

# function to scan selected IPs with VirusTotal
def scan_ips_vt(api_key, ips):
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"}
    for ip in ips:
        params = {"apikey": api_key, "ip": ip}
        response = requests.get(url, headers=headers, params=params)
        json = response.json()
        st.write(f"Results for {ip}:")
        if "detected_urls" in json:
            for detected_url in json["detected_urls"]:
                st.write(detected_url["url"])
        else:
            st.write("No malicious URLs detected.")
def main():
    st.set_page_config(page_title="PCAP Analyzer", page_icon=":shark:", layout="wide")

    st.title("PCAP Analyzer")
    st.markdown("Upload a PCAP file and extract information from it.")
    st.write("---")

    # Upload PCAP file
    pcap_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if pcap_file:
        # Display loading bar while file is being loaded
        with st.spinner("Loading PCAP file..."):
            # Convert PCAP file to Pandas DataFrame
            df = pcap_to_dataframe(pcap_file)

        st.success("PCAP file loaded successfully!")

        # Create check box for each public IP address found
        public_ips = extract_public_ips(df)
        public_ips_selected = st.multiselect("Select public IP addresses to scan with VirusTotal", public_ips)

        # Display VirusTotal API key input box
        vt_api_key = st.text_input("Enter your VirusTotal API key")

        # Check if at least one public IP address is selected and an API key is provided
        if public_ips_selected and vt_api_key:
            # Create dictionary to store VirusTotal scan results for each selected IP address
            vt_results = {}

            # Display loading bar while VirusTotal scans are running
            with st.spinner("Scanning selected IPs with VirusTotal..."):
                for ip in public_ips_selected:
                    # Scan IP address with VirusTotal
                    results = scan_with_virustotal(ip, vt_api_key)

                    # Store scan results in dictionary
                    vt_results[ip] = results

            st.success("VirusTotal scans completed!")

            # Display VirusTotal scan results
            st.write("---")
            st.subheader("VirusTotal Scan Results")

            for ip, results in vt_results.items():
                st.write(f"### {ip}")
                st.write(results)

        # Display raw data table
        st.write("---")
        st.subheader("Raw Data")
        st.write(df)

        # Display sorted data table
        st.write("---")
        st.subheader("Sorted Data")
        sort_by = st.selectbox("Sort by:", ["Source IP", "Source Port (TCP)", "Destination IP", "Destination Port (TCP)"])
        sorted_df = sort_dataframe(df, sort_by)
        st.write(sorted_df)

    else:
        st.warning("Please upload a PCAP file.")


if __name__ == "__main__":
    main()
