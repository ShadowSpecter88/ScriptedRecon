#!/usr/bin/env python3

import nmap
import argparse

def scan_network(target_range):
    nm = nmap.PortScanner()
    ports = '22,80,443,8443'
    print(f"Scanning {target_range} for open management ports...")
    nm.scan(hosts=target_range, ports=ports, arguments='-sV')
    vulnerable_devices = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service = nm[host][proto][port]
                product = service.get('product', '')
                version = service.get('version', '')
                extrainfo = service.get('extrainfo', '')
                if 'Palo Alto' in product or 'PaloAlto' in product or 'PAN' in product:
                    device_info = {
                        'host': host,
                        'port': port,
                        'protocol': proto,
                        'service': service.get('name', ''),
                        'product': product,
                        'version': version,
                        'extrainfo': extrainfo
                    }
                    vulnerable_devices.append(device_info)
                    print(f"Potential PAN device found at {host}:{port}")
                    print(f"Service: {service.get('name', '')}")
                    print(f"Product: {product} {version}")
                    print(f"Extra Info: {extrainfo}\n")

    if not vulnerable_devices:
        print("No potential PAN devices found with exposed management interfaces.")
    else:
        print(f"Total potential vulnerable devices found: {len(vulnerable_devices)}")

def main():
    parser = argparse.ArgumentParser(description='Scan network for vulnerable PAN devices.')
    parser.add_argument('-t', '--target', required=True, help='Target IP range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    scan_network(args.target)

if __name__ == '__main__':
    main()
