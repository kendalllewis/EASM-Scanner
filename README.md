EASM Scanner with SQLite Parser and Grafana Dashboard
Overview
This project provides a comprehensive solution for External Attack Surface Management (EASM), combining network scanning, data parsing, and visualization. It uses masscan, Nmap, and WhatWeb to identify and analyze open services, web technologies, and potential vulnerabilities across a target network. The results are parsed into a SQLite database for storage and further analysis. A Grafana JSON model is also included for visualizing the scan data through a dynamic and multi-panel dashboard.

Features
Automated Scanning Workflow
Uses masscan for high-speed port scanning.
Performs detailed service and version detection with Nmap.
Analyzes web server technologies with WhatWeb.
Data Parsing and Storage
Parses masscan, Nmap, and WhatWeb results into a structured SQLite database.
Supports detailed data storage for hosts, open ports, services, and web technologies.
Handles errors gracefully to ensure consistent data insertion.
Visualization with Grafana
Provides a comprehensive Grafana JSON model for creating a multi-panel dashboard.
Dashboard panels include total hosts, total ports, open services by type, ports per host, HTTP details, SSL certificate information, and more.
Facilitates data-driven decision-making by presenting scan results in an easily interpretable format.
Components
EASM Scanner:
Executes scanning tasks using masscan, Nmap, and WhatWeb for a target IP range or list of ranges.
Supports command-line arguments to specify scan options, including packet rate, Nmap scripts, and WhatWeb scan levels.
SQLite Parser:
Parses the combined scan results and stores the data in an SQLite database.
Database schema includes tables for hosts, ports, and WhatWeb results, with fields for IP, service details, web plugins, SSL information, etc.
Grafana JSON Model:
JSON configuration for creating a Grafana dashboard.
Pre-configured panels for visualizing network scan data, including tables and charts for service distribution, host analysis, and web technologies.
Supports interactive filtering and drill-down capabilities.
How to Use
Run the Scans:

Execute the EASM Scanner to perform scans on your target network.
Supports both individual IP ranges and batch scanning from a file.
Parse the Results:

Use the SQLite Parser script to parse the XML output from the scans and populate the SQLite database.
Visualize with Grafana:

Import the provided Grafana JSON model into your Grafana instance.
Connect Grafana to the SQLite database or use a middleware service to serve the data as a REST API.
Prerequisites
masscan, Nmap, WhatWeb installed on your system.
Python 3.x with the sqlite3 library.
Grafana for dashboard visualization.
Example Commands
bash
Copy code
# Run the EASM Scanner with masscan, Nmap, and WhatWeb
python easm_scanner.py --ip_range 192.168.1.0/24 --rate 1000 --nmap_options "-sV" --scan_level 3

![image](https://github.com/user-attachments/assets/7ee07187-cae5-4708-8cd2-797090b452a7)


# Parse the scan results into the SQLite database
python nmap_to_sqlite.py /path/to/final_scan_results.xml /path/to/whatweb_results.xml

# Export scan results to JSON for Grafana
python export_to_json.py
