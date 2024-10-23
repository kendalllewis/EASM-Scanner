import argparse
import subprocess
import os
import xml.etree.ElementTree as ET

with open("art.txt") as f:
     print(f.read())

def run_masscan(ip_ranges, rate):
    # Run masscan for all ports on the provided ranges
    for ip_range in ip_ranges:
        output_file = f"masscan_output_{ip_range.replace('/', '_')}.xml"
        masscan_cmd = f"masscan {ip_range} -p1-65535 --rate={rate} -oX {output_file}"
        subprocess.run(masscan_cmd, shell=True)
        print(f"[+] Masscan completed for {ip_range}.")

def parse_masscan_output():
    # Parse all masscan XML outputs and format for nmap input
    hosts = {}
    for file in os.listdir():
        if file.startswith("masscan_output") and file.endswith(".xml"):
            try:
                tree = ET.parse(file)
                root = tree.getroot()

                for host in root.findall("host"):
                    address_elem = host.find("address")
                    if address_elem is not None:
                        ip = address_elem.attrib.get("addr", "")
                        ports = []
                        for port in host.findall("ports/port"):
                            port_id = port.attrib.get("portid", "")
                            if port_id:
                                ports.append(port_id)
                        if ip and ports:
                            if ip in hosts:
                                hosts[ip].extend(ports)
                            else:
                                hosts[ip] = ports
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    # Create nmap input format "ip -p port1,port2,..."
    nmap_targets = [f"{ip} -p {','.join(ports)}" for ip, ports in hosts.items() if ports]
    return nmap_targets

def run_nmap(targets, nmap_options):
    # Run nmap scan
    for target in targets:
        ip = target.split()[0]
        output_file = f"nmap_output_{ip}.xml"
        nmap_cmd = f"nmap -sV {nmap_options} {target} -oX {output_file}"
        subprocess.run(nmap_cmd, shell=True)
    print("[+] Nmap scan completed.")

def run_whatweb(targets, scan_level):
    # Run whatweb against web servers and output results in XML format
    for target in targets:
        ip = target.split()[0]
        whatweb_cmd = f"whatweb -a {scan_level} {ip} --log-xml=whatweb_output_{ip}.xml"
        subprocess.run(whatweb_cmd, shell=True)
    print("[+] Whatweb scan completed.")

def merge_results():
    # Merge masscan, nmap, and whatweb outputs into a single XML
    root = ET.Element("scan_results")

    # Merge masscan results
    for file in os.listdir():
        if file.startswith("masscan_output") and file.endswith(".xml"):
            try:
                masscan_tree = ET.parse(file)
                masscan_root = masscan_tree.getroot()
                root.append(masscan_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    # Merge nmap results
    for file in os.listdir():
        if file.startswith("nmap_output") and file.endswith(".xml"):
            try:
                nmap_tree = ET.parse(file)
                nmap_root = nmap_tree.getroot()
                root.append(nmap_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    # Merge whatweb results
    for file in os.listdir():
        if file.startswith("whatweb_output") and file.endswith(".xml"):
            try:
                whatweb_tree = ET.parse(file)
                whatweb_root = whatweb_tree.getroot()
                root.append(whatweb_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    # Write to final XML
    tree = ET.ElementTree(root)
    tree.write("final_scan_results.xml")
    print("[+] Final results merged into 'final_scan_results.xml'.")

def setup_argparse():
    parser = argparse.ArgumentParser(description="Comprehensive EASM Scanner: Masscan, Nmap, and WhatWeb")
    parser.add_argument("--ip_range", help="IP range to scan")
    parser.add_argument("--input_file", help="File containing multiple IP ranges")
    parser.add_argument("--rate", default=1000, help="Rate of packets for masscan")
    parser.add_argument("--nmap_options", default="", help="Additional nmap options")
    parser.add_argument("--scan_level", default=3, type=int, help="Whatweb scan level (1-4)")
    return parser.parse_args()

def read_ip_ranges(args):
    # Read IP ranges from input file or directly from argument
    ip_ranges = []
    if args.input_file:
        with open(args.input_file, "r") as file:
            ip_ranges = [line.strip() for line in file if line.strip()]
    elif args.ip_range:
        ip_ranges = [args.ip_range]
    else:
        print("Error: You must provide an IP range or input file with ranges.")
        exit(1)
    return ip_ranges

def main():
    args = setup_argparse()
    ip_ranges = read_ip_ranges(args)

    # Run scans
    run_masscan(ip_ranges, args.rate)
    nmap_targets = parse_masscan_output()
    if not nmap_targets:
        print("[!] No targets found from masscan results.")
        return
    run_nmap(nmap_targets, args.nmap_options)
    run_whatweb(nmap_targets, args.scan_level)

    # Merge results
    merge_results()

    # Provide instructions for Grafana dashboard setup
    print("[+] To visualize, first parse 'final_scan_results.xml' into Sqlite3 database using create_db.py. This will create a scan_results.db that may be used to feed Grafana Dashboards or custom web dashboards using sqlite queries in Grafana.")

if __name__ == "__main__":
    main()

