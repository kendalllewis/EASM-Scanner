import sqlite3
import xml.etree.ElementTree as ET

def create_database():
    # Create the SQLite3 database and tables
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create hosts table
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        state TEXT)''')

    # Create ports table
    cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        port INTEGER,
                        protocol TEXT,
                        state TEXT,
                        service TEXT,
                        product TEXT,
                        version TEXT,
                        ssl_common_name TEXT,
                        ssl_issuer TEXT,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    # Create WhatWeb table for web application details
    cursor.execute('''CREATE TABLE IF NOT EXISTS whatweb (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        url TEXT,
                        plugin TEXT,
                        version TEXT,
                        description TEXT,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    conn.commit()
    conn.close()

def parse_nmap_and_whatweb_to_db(nmap_file, whatweb_file):
    # Connect to the SQLite3 database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Parse Nmap XML
    tree = ET.parse(nmap_file)
    root = tree.getroot()

    for host in root.findall(".//host"):
        try:
            ip = host.find("address").attrib.get("addr")
            state = host.find("status").attrib.get("state", "unknown")

            # Insert host data into the database
            cursor.execute("INSERT INTO hosts (ip, state) VALUES (?, ?)", (ip, state))
            host_id = cursor.lastrowid

            # Insert ports data
            for port in host.findall(".//port"):
                port_id = int(port.attrib.get("portid", 0))
                protocol = port.attrib.get("protocol", "tcp")
                port_state = port.find("state").attrib.get("state", "unknown")
                service = port.find("service").attrib.get("name", "unknown") if port.find("service") is not None else None
                product = port.find("service").attrib.get("product", "") if port.find("service") is not None else ""
                version = port.find("service").attrib.get("version", "") if port.find("service") is not None else ""
                
                # SSL information from scripts
                ssl_common_name = None
                ssl_issuer = None
                for script in port.findall(".//script[@id='ssl-cert']"):
                    for table in script.findall(".//table"):
                        if table.get("key") == "subject":
                            ssl_common_name = table.find("elem[@key='commonName']").text if table.find("elem[@key='commonName']") is not None else None
                        elif table.get("key") == "issuer":
                            ssl_issuer = table.find("elem[@key='commonName']").text if table.find("elem[@key='commonName']") is not None else None

                # Insert port data into the database
                cursor.execute('''INSERT INTO ports (host_id, port, protocol, state, service, product, version, ssl_common_name, ssl_issuer)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                                  (host_id, port_id, protocol, port_state, service, product, version, ssl_common_name, ssl_issuer))

        except AttributeError:
            # Skip the host if required attributes are missing
            continue

    # Parse WhatWeb XML (if provided)
    if whatweb_file and os.path.exists(whatweb_file):
        tree = ET.parse(whatweb_file)
        root = tree.getroot()

        for target in root.findall(".//target"):
            try:
                url = target.attrib.get("url")
                ip = url.split("/")[2] if "://" in url else url.split("/")[0]

                # Find the corresponding host_id
                cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
                host_row = cursor.fetchone()
                if host_row:
                    host_id = host_row[0]

                    for plugin in target.findall("plugins/plugin"):
                        plugin_name = plugin.attrib.get("name")
                        plugin_version = plugin.attrib.get("version", "")
                        description = plugin.attrib.get("description", "")

                        # Insert WhatWeb data into the database
                        cursor.execute('''INSERT INTO whatweb (host_id, url, plugin, version, description)
                                          VALUES (?, ?, ?, ?, ?)''', 
                                          (host_id, url, plugin_name, plugin_version, description))

            except Exception as e:
                # Handle parsing errors gracefully
                print(f"Error parsing WhatWeb XML: {e}")
                continue

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Create the database and tables
create_database()

# Parse Nmap and WhatWeb files and insert data into the database
parse_nmap_and_whatweb_to_db("final_scan_results.xml", "whatweb_results.xml")

