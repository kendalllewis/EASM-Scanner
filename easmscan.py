import argparse
import subprocess
import os
import xml.etree.ElementTree as ET

# Function to read contents of a file and print
def read_art_file():
    try:
        with open("art.txt") as f:
            print(f.read())
    except FileNotFoundError:
        print("[!] art.txt file not found.")

# List of common UDP ports for scanning, which may be added to at any time
COMMON_UDP_PORTS = "53,67,68,69,123,137,161,162,500,514,520,623,1900,3391,4500,5353,5683"

# Run Masscan for TCP/UDP
def run_masscan(ip_ranges, rate, udp=False):
    rate = int(rate)
    for ip_range in ip_ranges:
        protocol = "U" if udp else "1-65535"
        output_file = f"masscan_output_{'udp' if udp else 'tcp'}_{ip_range.replace('/', '_')}.xml"
        masscan_cmd = f"masscan {ip_range} -p{protocol} --rate={rate // (10 if udp else 1)} -oX {output_file}"
        subprocess.run(masscan_cmd, shell=True)
        print(f"[+] Masscan {'UDP' if udp else 'TCP'} scan completed for {ip_range}.")

# Run Unicornscan for UDP
def run_unicornscan(ip_range, udp_ports):
    output_file = f"unicornscan_output_udp_{ip_range.replace('/', '_')}.txt"
    cmd = f"unicornscan -mU -p {udp_ports} {ip_range} > {output_file}"
    subprocess.run(cmd, shell=True)
    print(f"[+] Unicornscan UDP scan completed for {ip_range}.")
    return output_file

# Parse Masscan output
def parse_masscan_output(udp=False):
    hosts = {}
    protocol = "udp" if udp else "tcp"
    for file in os.listdir():
        if file.startswith(f"masscan_output_{protocol}") and file.endswith(".xml"):
            try:
                tree = ET.parse(file)
                root = tree.getroot()
                for host in root.findall("host"):
                    ip = host.find("address").attrib.get("addr", "")
                    ports = [port.attrib.get("portid", "") for port in host.findall("ports/port")]
                    if ip and ports:
                        hosts[ip] = hosts.get(ip, []) + ports
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")
    return hosts

# Run Nmap for targeted hosts
def run_nmap(targets, nmap_options, udp=False):
    scan_type = "-sU" if udp else "-sS"
    protocol = "udp" if udp else "tcp"
    for target in targets:
        ip, ports = target
        output_file = f"nmap_output_{ip}_{protocol}.xml"
        nmap_cmd = f"nmap {scan_type} {nmap_options} -p {ports} {ip} -oX {output_file}"
        subprocess.run(nmap_cmd, shell=True)
        print(f"[+] Nmap {'UDP' if udp else 'TCP'} scan completed for {ip}.")

# Perform an indirect UDP scan using Nmap, which we have found to be effective when run on a host with tcp port found
def indirect_udp_scan(host, tcp_port, udp_port):
    cmd = f"nmap -p {tcp_port},U:{udp_port} -sSU {host} -oX nmap_indirect_{host}_{udp_port}.xml"
    subprocess.run(cmd, shell=True)
    print(f"[+] Indirect scan for UDP port {udp_port} via TCP {tcp_port} on {host}.")

# Run passive OS fingerprinting with p0f, which is in testing now. Not sure about this
def run_p0f(ip_range):
    cmd = f"p0f -i eth0 -o p0f_output_{ip_range.replace('/', '_')}.txt &"
    subprocess.run(cmd, shell=True)
    print(f"[+] Passive OS fingerprinting with p0f initiated for {ip_range}.")

# Run WhatWeb for web service analysis, which may include following all redirects in the future
def run_whatweb(targets, scan_level):
    for target in targets:
        whatweb_cmd = f"whatweb -a {scan_level} {target} --open-timeout 6 --read-timeout 6 --log-xml=whatweb_output_{target.replace('.', '_')}.xml"
        subprocess.run(whatweb_cmd, shell=True)
    print("[+] WhatWeb scan completed.")

# Perform reverse DNS lookup with dig, which is good for virtual web assets or multiple web instances running at one IP
def run_dig(ip):
    ptr_records = []
    try:
        dig_ptr_cmd = f"dig -x {ip} +short"
        ptr_results = subprocess.check_output(dig_ptr_cmd, shell=True, text=True).strip().splitlines()
        ptr_records = [record.strip('.') for record in ptr_results if record]
        print(f"[+] PTR records for {ip}: {ptr_records}")
    except subprocess.CalledProcessError as e:
        print(f"[!] dig command failed for {ip}: {e}")
    return ptr_records

# Merge all scan outputs into a single XML file
def merge_results():
    root = ET.Element("scan_results")
    for file in os.listdir():
        if file.endswith(".xml") and ("masscan" in file or "nmap" in file or "whatweb" in file):
            try:
                tree = ET.parse(file)
                root.append(tree.getroot())
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")
    tree = ET.ElementTree(root)
    tree.write("final_scan_results.xml")
    print("[+] Final results merged into 'final_scan_results.xml'.")

# Set up command-line argument parsing
def setup_argparse():
    parser = argparse.ArgumentParser(description="Comprehensive EASM Scanner")
    parser.add_argument("--ip_range", help="IP range to scan")
    parser.add_argument("--input_file", help="File containing multiple IP ranges")
    parser.add_argument("--rate", default=1000, help="Rate of packets for masscan")
    parser.add_argument("--nmap_options", default="", help="Additional Nmap options")
    parser.add_argument("--scan_level", default=3, type=int, help="WhatWeb scan level (1-4)")
    parser.add_argument("--passive_os", action="store_true", help="Enable passive OS fingerprinting with p0f")
    return parser.parse_args()

# Read IP ranges from argument or file
def read_ip_ranges(args):
    if args.input_file:
        with open(args.input_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    elif args.ip_range:
        return [args.ip_range]
    else:
        print("Error: You must provide an IP range or input file with ranges.")
        exit(1)

# Main scanning workflow
def main():

    read_art_file()  # Read and display art.txt file at the start

    args = setup_argparse()
    ip_ranges = read_ip_ranges(args)

    # Step 1: Run TCP Masscan
    run_masscan(ip_ranges, args.rate)
    hosts_tcp = parse_masscan_output()
    nmap_targets_tcp = [(ip, ",".join(ports)) for ip, ports in hosts_tcp.items()]
    run_nmap(nmap_targets_tcp, args.nmap_options)

    # Step 2: Run Unicornscan for UDP and parse results
    hosts_udp = {}
    for ip_range in ip_ranges:
        unicornscan_output = run_unicornscan(ip_range, COMMON_UDP_PORTS)
        hosts_udp.update(parse_masscan_output(udp=True))

    # Step 3: Perform indirect UDP scans via TCP ports
    for host, tcp_ports in hosts_tcp.items():
        for udp_port in COMMON_UDP_PORTS.split(","):
            indirect_udp_scan(host, tcp_ports[0], udp_port)

    # Step 4: Run WhatWeb and p0f (if requested)
    ptr_targets = {ip for ip in hosts_tcp.keys() for record in run_dig(ip)}
    if ptr_targets:
        run_whatweb(ptr_targets, args.scan_level)
    if args.passive_os:
        run_p0f(args.ip_range)

    # Step 5: Merge results
    merge_results()

if __name__ == "__main__":
    main()
