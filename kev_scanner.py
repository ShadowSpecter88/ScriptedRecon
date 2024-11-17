#!/usr/bin/env python3
import argparse
import pandas as pd
import requests
import subprocess

def scan_network(network_range):
    result = subprocess.run(['nmap', '-O', network_range], capture_output=True, text=True)
    return result.stdout

def parse_nmap_output(nmap_output):
    devices = []
    lines = nmap_output.split('\n')
    current_device = {}
    for line in lines:
        if 'Nmap scan report for' in line:
            if current_device:
                devices.append(current_device)
                current_device = {}
            current_device['ip'] = line.split(' ')[-1]
        elif 'OS details:' in line:
            current_device['os'] = line.replace('OS details: ', '').strip()
        elif 'Device type:' in line:
            current_device['device_type'] = line.replace('Device type: ', '').strip()
    if current_device:
        devices.append(current_device)
    return devices

def process_csv_data(url):
    response = requests.get(url)
    with open("known_exploited_vulnerabilities.csv", "wb") as f:
        f.write(response.content)
    df = pd.read_csv("known_exploited_vulnerabilities.csv")
    df["dateAdded"] = pd.to_datetime(df["dateAdded"])
    df["cveID"] = df["cveID"].str.lower()
    df["vendorProject"] = df["vendorProject"].str.lower()
    df["product"] = df["product"].str.lower()
    return df, df.copy()

def filter_data(df, search_input):
    search_input_parts = search_input.split(":")
    if len(search_input_parts) == 2:
        start_date, end_date = search_input_parts
        return df[(df["dateAdded"] >= start_date) & (df["dateAdded"] <= end_date)]
    return df[(df["cveID"] == search_input) | (df["vendorProject"] == search_input) | (df["product"].str.contains(search_input))]

def analyze_network(df, network):
    nmap_output = scan_network(network)
    devices = parse_nmap_output(nmap_output)
    vulnerable_devices = []
    for device in devices:
        vendor = device.get('os', '').split(' ')[0].lower()
        if vendor:
            matching_vulns = df[df['vendorProject'] == vendor]
            if not matching_vulns.empty:
                vulnerable_devices.append({'ip': device['ip'], 'vendor': vendor, 'vulnerabilities': matching_vulns['cveID'].tolist()})
    return vulnerable_devices

def main():
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    df, df_original_case = process_csv_data(url)
    parser = argparse.ArgumentParser(description='Retrieve and process CISA KEV data.')
    parser.add_argument('search', type=str, help='Search term or time range "YYYY-MM-DD:YYYY-MM-DD".')
    parser.add_argument('--network', type=str, help='Network range to scan.')
    args = parser.parse_args()
    filtered_df = filter_data(df, args.search.lower())
    filtered_df_original_case = df_original_case.loc[filtered_df.index]
    pd.options.display.max_rows = None
    print(filtered_df_original_case[["cveID", "vendorProject", "product"]])
    if args.network:
        vulnerable_devices = analyze_network(filtered_df, args.network)
        for vd in vulnerable_devices:
            print(f"IP: {vd['ip']}, Vendor: {vd['vendor']}, Vulnerabilities: {vd['vulnerabilities']}")

if __name__ == '__main__':
    main()
