EASM Scanner with SQLite Parser and Grafana Dashboard

Overview

This project provides a simple solution for External Attack Surface Management (EASM), combining network scanning, data parsing, and visualization. After running into a situation where the commercial tool we were using raised their prices astronomically, we needed to look for a cheaper replacement. I think Spiderfoot is a great OSINT tool, but we still needed a true scanner to stay on top of our external attack surface (ports, services, assets, status, etc). Solutions available were either way too expensive or were just scripts to run Masscan and Nmap. We needed a fast tool that would provide automated scanning and parsing dynamically, but also needed dashboard functionality. This tool leverages masscan, Nmap, and WhatWeb to identify and analyze open services, web technologies, and potential vulnerabilities across a target network. The results are parsed into a SQLite database for storage and further analysis. A Grafana JSON model is created from the results and is included for visualizing the scan data through a dynamic and multi-panel dashboard. We will work on scheduling functionality soon, so that we can set and forget on the scanning and parsing piece and focus on watching the dashboards, data, and metrics. This will allow us to do our primary job of tracking vulnerabilities, exploiting vulnerabilities, and looking for the "unintended".

This project is really an extension of the great work done by Hackertarget https://github.com/hackertarget/nmap-did-what/, but we needed to improve of scanning capabilities, adding more context to dashboards, and plan for a framework we can grow into.

Features

-Automated Scanning Workflow

-Uses masscan for high-speed port scanning.

-Performs detailed service and version detection with Nmap.

-Analyzes web server technologies with WhatWeb.

-Data Parsing and Storage

-Parses masscan, Nmap, and WhatWeb results into a structured SQLite database.

-Supports detailed data storage for hosts, open ports, services, and web technologies.

-Handles errors gracefully to ensure consistent data insertion.

-Visualization with Grafana

-Provides a comprehensive Grafana JSON model for creating a multi-panel dashboard.

-Dashboard panels include total hosts, total ports, open services by type, ports per host, HTTP details, SSL certificate information, and more.

-Facilitates data-driven decision-making by presenting scan results in an easily interpretable format.

Components

EASM Scanner:
Executes scanning tasks using masscan, Nmap, and WhatWeb for a target IP range or list of ranges.
Supports command-line arguments to specify scan options, including packet rate, Nmap scripts, and WhatWeb scan levels.

SQLite Parser:
Parses the combined scan results and stores the data in an SQLite database.
Database schema includes tables for hosts, ports, and WhatWeb results, with fields for IP, service details, web plugins, SSL information, etc.

Grafana JSON Model:
JSON configuration for creating a Grafana dashboard. There are some available in the Grafana public repository, which you can customize once imported.
Pre-configured panels for visualizing network scan data, including tables and charts for service distribution, host analysis, and web technologies.
Supports interactive filtering and drill-down capabilities.

How to Use

1. Run the Scans:

Execute the EASM Scanner to perform scans on your target network.
Supports both individual IP ranges and batch scanning from a file.

2. Parse the Results:

Use the SQLite Parser script to parse the XML output from the scans and populate the SQLite database. 

3. Visualize with Grafana:

Establish a Grafana JSON model in your Grafana instance.
Connect Grafana to the SQLite database or use a middleware service to serve the data as a REST API. I would love to get there soon.

Prerequisites
-Masscan, Nmap, WhatWeb installed on your system.
-Python 3.x with the sqlite3 library.
-Docker and Grafana for dashboard visualization.

Example Commands and Sequence

# Run the EASM Scanner with masscan, Nmap, and WhatWeb
1. python3 easmscan.py --ip_range 192.168.1.0/24 --rate 10000 --nmap_options "-sV" --scan_level 3
Note: This will produce the final_scan_results.xml file that will be used to create the SQLite3 database for Grafana Dashboards.
![image](https://github.com/user-attachments/assets/8244884d-3d11-4367-a085-6112be42ae8d)

# Create the database:
2. python3 create_db.py

# Parse the scan results into the SQLite database
3. Create_db.py will use final_scan_results.xml and will produce a scan_results.db that may be used as the datasource in Grafana for dashboards.

4. Move to Grafana and build dashboards.


I will be adding a section to cover building a container for Grafana and then setting up some common dashboards in Grafana.
