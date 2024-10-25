import argparse
import subprocess
import os
import xml.etree.ElementTree as ET

def run_masscan(ip_ranges, rate):
    for ip_range in ip_ranges:
        output_file = f"masscan_output_{ip_range.replace('/', '_')}.xml"
        masscan_cmd = f"masscan {ip_range} -p1-65535 --rate={rate} -oX {output_file}"
        subprocess.run(masscan_cmd, shell=True)
        print(f"[+] Masscan completed for {ip_range}.")

def parse_masscan_output():
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
    nmap_targets = [f"{ip} -p {','.join(ports)}" for ip, ports in hosts.items() if ports]
    return hosts, nmap_targets

def run_nmap(targets, nmap_options):
    for target in targets:
        ip = target.split()[0]
        output_file = f"nmap_output_{ip}.xml"
        nmap_cmd = f"nmap -sV {nmap_options} {target} -oX {output_file}"
        subprocess.run(nmap_cmd, shell=True)
    print("[+] Nmap scan completed.")

def run_whatweb(targets, scan_level):
    for target in targets:
        whatweb_cmd = f"whatweb -a {scan_level} {target} --open-timeout 6 --read-timeout 6 --log-xml=whatweb_output_{target.replace('.', '_')}.xml"
        subprocess.run(whatweb_cmd, shell=True)
    print("[+] WhatWeb scan completed.")

def run_dig(ip):
    ptr_records = []
    try:
        dig_ptr_cmd = f"dig -x {ip} +short"
        ptr_results = subprocess.check_output(dig_ptr_cmd, shell=True, text=True).strip().splitlines()
        if ptr_results:
            ptr_records = [record.strip('.') for record in ptr_results]
            print(f"[+] PTR records for {ip}: {ptr_records}")
    except subprocess.CalledProcessError as e:
        print(f"[!] dig command failed for {ip}: {e}")
    return ptr_records

def merge_results(dns_results):
    root = ET.Element("scan_results")

    for file in os.listdir():
        if file.startswith("masscan_output") and file.endswith(".xml"):
            try:
                masscan_tree = ET.parse(file)
                masscan_root = masscan_tree.getroot()
                root.append(masscan_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    for file in os.listdir():
        if file.startswith("nmap_output") and file.endswith(".xml"):
            try:
                nmap_tree = ET.parse(file)
                nmap_root = nmap_tree.getroot()
                root.append(nmap_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    for file in os.listdir():
        if file.startswith("whatweb_output") and file.endswith(".xml"):
            try:
                whatweb_tree = ET.parse(file)
                whatweb_root = whatweb_tree.getroot()
                root.append(whatweb_root)
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")

    tree = ET.ElementTree(root)
    tree.write("final_scan_results.xml")
    print("[+] Final results merged into 'final_scan_results.xml'.")

def setup_argparse():
    parser = argparse.ArgumentParser(description="Comprehensive EASM Scanner")
    parser.add_argument("--ip_range", help="IP range to scan")
    parser.add_argument("--input_file", help="File containing multiple IP ranges")
    parser.add_argument("--rate", default=1000, help="Rate of packets for masscan")
    parser.add_argument("--nmap_options", default="", help="Additional Nmap options")
    parser.add_argument("--scan_level", default=3, type=int, help="WhatWeb scan level (1-4)")
    return parser.parse_args()

def read_ip_ranges(args):
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

    run_masscan(ip_ranges, args.rate)
    hosts, nmap_targets = parse_masscan_output()
    if not nmap_targets:
        print("[!] No targets found from Masscan results.")
        return

    run_nmap(nmap_targets, args.nmap_options)

    # Step 1: Run dig to find PTR records
    ptr_targets = set()
    for ip in hosts.keys():
        ptr_records = run_dig(ip)
        ptr_targets.update(ptr_records)

    # Step 2: Run WhatWeb against each PTR record
    if ptr_targets:
        run_whatweb(ptr_targets, args.scan_level)

    # Merge all results
    merge_results({})
    print("[+] To visualize, parse 'final_scan_results.xml' into a SQLite database using create_db.py.")

if __name__ == "__main__":
    main()

