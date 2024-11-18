from scapy.all import sniff
from datetime import datetime
import csv
import requests
import time
import os

WIGLE_API_URL = "https://api.wigle.net/api/v2/network/search"
WIGLE_USERNAME = os.getenv("WIGLE_USERNAME")
WIGLE_API_KEY = os.getenv("WIGLE_API_KEY")
LOG_FILE = "wifi_probe_requests_with_wigle.csv"
RATE_LIMIT_DELAY = 1.5  # Adjust to match WiGLE API limits

def query_wigle(mac_address):
    if not WIGLE_USERNAME or not WIGLE_API_KEY:
        raise ValueError("WiGLE credentials are not set.")
    try:
        response = requests.get(
            WIGLE_API_URL,
            auth=(WIGLE_USERNAME, WIGLE_API_KEY),
            params={"netid": mac_address},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        if data.get("results"):
            network = data["results"][0]
            return {
                "SSID": network.get("ssid", "Unknown"),
                "Country": network.get("country", "Unknown"),
                "City": network.get("city", "Unknown"),
                "Latitude": network.get("trilat", "Unknown"),
                "Longitude": network.get("trilong", "Unknown"),
            }
        return None
    except requests.exceptions.RequestException as e:
        print(f"WiGLE query failed for {mac_address}: {e}")
        return None

def is_valid_mac(mac):
    return mac and len(mac) == 17 and all(c in "0123456789ABCDEFabcdef:-" for c in mac)

def log_packet(packet):
    if packet.haslayer("Dot11ProbeReq"):
        mac = packet.addr2
        if not is_valid_mac(mac):
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        wigle_data = query_wigle(mac) if WIGLE_USERNAME and WIGLE_API_KEY else None

        ssid = wigle_data.get("SSID") if wigle_data else "Unknown"
        country = wigle_data.get("Country") if wigle_data else "Unknown"
        city = wigle_data.get("City") if wigle_data else "Unknown"
        latitude = wigle_data.get("Latitude") if wigle_data else "Unknown"
        longitude = wigle_data.get("Longitude") if wigle_data else "Unknown"

        with open(LOG_FILE, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, mac, ssid, country, city, latitude, longitude])
        time.sleep(RATE_LIMIT_DELAY)

def main():
    iface = os.getenv("SNIFF_INTERFACE", "wlan0")
    with open(LOG_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "MAC Address", "SSID", "Country", "City", "Latitude", "Longitude"])

    print(f"Sniffing on interface {iface}. Press Ctrl+C to stop.")
    try:
        sniff(iface=iface, prn=log_packet, store=False, monitor=True)
    except Exception as e:
        print(f"Error during sniffing: {e}")

if __name__ == "__main__":
    main()
