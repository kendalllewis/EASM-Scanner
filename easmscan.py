import argparse
import subprocess
import os
import concurrent.futures
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

# Run Nmap for targeted hosts with user-defined options
def run_nmap(targets, nmap_options, udp=False):
    scan_type = "-sU" if udp else "-sS"
    protocol = "udp" if udp else "tcp"
    for target in targets:
        ip, ports = target
        output_file = f"nmap_output_{ip}_{protocol}.xml"
        nmap_cmd = f"nmap {scan_type} {nmap_options} -p {ports} {ip} -oX {output_file}"
        subprocess.run(nmap_cmd, shell=True)
        print(f"[+] Nmap {'UDP' if udp else 'TCP'} scan with options '{nmap_options}' completed for {ip}.")

# Perform an indirect UDP scan using Nmap, filtering for open results on UDP ports only
def indirect_udp_scan(host, tcp_port, udp_port):
    temp_output_file = f"nmap_indirect_{host}_{udp_port}_temp.xml"
    cmd = f"nmap -p {tcp_port},U:{udp_port} -sSU {host} --host-timeout 10m --max-retries 2 -oX {temp_output_file}"
    subprocess.run(cmd, shell=True)
    try:
        tree = ET.parse(temp_output_file)
        root = tree.getroot()
        open_udp_found = False

        # Iterate over each port in the scan results
        for port in root.findall(".//port"):
            protocol = port.attrib.get("protocol", "")
            state = port.find("state").attrib.get("state", "")

            # Check only UDP ports and look for open state
            if protocol == "udp" and state == "open":
                open_udp_found = True
                service_element = port.find("service")
                service = service_element.attrib.get("name", "unknown") if service_element is not None else "unknown"
                print(f"port:{udp_port}/udp state:open service:{service}")

        # Only save the result if an open UDP port is found
        if open_udp_found:
            final_output_file = f"nmap_indirect_{host}_{udp_port}.xml"
            os.rename(temp_output_file, final_output_file)
            print(f"[+] Created {final_output_file} for host {host} on UDP port {udp_port}.")
        else:
            os.remove(temp_output_file)
            print(f"[!] No open UDP ports found for {host} on port {udp_port}; skipped file creation.")

    except ET.ParseError:
        print(f"[!] Error parsing {temp_output_file}. Skipping.")
        os.remove(temp_output_file)

# Run passive OS fingerprinting with p0f
def run_p0f(ip_range):
    cmd = f"p0f -i eth0 -o p0f_output_{ip_range.replace('/', '_')}.txt &"
    subprocess.run(cmd, shell=True)


# Perform reverse DNS lookup with dig
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
    read_art_file()  # Display art.txt file contents at the start
    args = setup_argparse()
    ip_ranges = read_ip_ranges(args)

    # Step 1: Run TCP Masscan
    run_masscan(ip_ranges, args.rate)
    hosts_tcp = parse_masscan_output()
    nmap_targets_tcp = [(ip, ",".join(ports)) for ip, ports in hosts_tcp.items()]
    run_nmap(nmap_targets_tcp, args.nmap_options)

    # Step 3: Perform indirect UDP scans via TCP ports
    for host, tcp_ports in hosts_tcp.items():
        for udp_port in COMMON_UDP_PORTS.split(","):
            indirect_udp_scan(host, tcp_ports[0], udp_port)

    # Step 4: Run WhatWeb and p0f (if requested)
    # Collect PTR records instead of IP addresses for WhatWeb targets
    ptr_targets = set()
    for ip in hosts_tcp.keys():
        ptr_records = run_dig(ip)
        ptr_targets.update(ptr_records)

    if ptr_targets:
        run_whatweb(ptr_targets, args.scan_level)
    if args.passive_os:
        run_p0f(args.ip_range)

    # Step 5: Merge results
    merge_results()

if __name__ == "__main__":
    main()
