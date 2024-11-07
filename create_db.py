import sqlite3
import xml.etree.ElementTree as ET

def create_database():
    # Create the SQLite3 database and tables
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create tables for hosts, ports (TCP and UDP), WhatWeb data, and certificates with 'updated_at' columns
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        os TEXT,
                        state TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    # Unified ports table for both TCP and UDP, differentiated by 'protocol' column
    cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        port INTEGER,
                        protocol TEXT CHECK(protocol IN ('tcp', 'udp')),
                        state TEXT,
                        service TEXT,
                        product TEXT,
                        version TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    # WhatWeb data table
    cursor.execute('''CREATE TABLE IF NOT EXISTS whatweb (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        url TEXT,
                        plugin TEXT,
                        version TEXT,
                        description TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    # Certificates table for SSL/TLS details
    cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        port INTEGER,
                        issuer TEXT,
                        subject TEXT,
                        valid_from TEXT,
                        valid_until TEXT,
                        expiration_days INTEGER,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    conn.commit()
    conn.close()

def create_triggers():
    # Connect to the database to create triggers
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create triggers for automatic timestamp updates
    tables = ["hosts", "ports", "whatweb", "certificates"]
    for table in tables:
        cursor.execute(f'''
            CREATE TRIGGER IF NOT EXISTS update_{table}_timestamp
            AFTER UPDATE ON {table}
            FOR EACH ROW
            BEGIN
                UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END;
        ''')

        cursor.execute(f'''
            CREATE TRIGGER IF NOT EXISTS insert_{table}_timestamp
            AFTER INSERT ON {table}
            FOR EACH ROW
            BEGIN
                UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        ''')

    conn.commit()
    conn.close()

def parse_xml_to_db(xml_file):
    # Connect to the SQLite3 database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Parse Nmap data
    for host in root.findall(".//host"):
        try:
            ip = host.find("address").attrib.get("addr")
            state = host.find("status").attrib.get("state", "unknown")
            hostname = host.find("hostnames/hostname").attrib.get("name", "unknown") if host.find("hostnames/hostname") is not None else None
            os_element = host.find("os/osmatch")
            os_name = os_element.attrib.get("name", "unknown") if os_element is not None else "unknown"

            # Insert host data
            cursor.execute("INSERT INTO hosts (ip, hostname, os, state) VALUES (?, ?, ?, ?)", (ip, hostname, os_name, state))
            host_id = cursor.lastrowid

            # Insert port data (both TCP and UDP)
            for port in host.findall(".//port"):
                port_id = int(port.attrib.get("portid", 0))
                protocol = port.attrib.get("protocol", "tcp")  # Identify protocol as 'tcp' or 'udp'
                port_state = port.find("state").attrib.get("state", "unknown")
                service = port.find("service").attrib.get("name", "unknown") if port.find("service") is not None else None
                product = port.find("service").attrib.get("product", "") if port.find("service") is not None else ""
                version = port.find("service").attrib.get("version", "") if port.find("service") is not None else ""

                # Insert port data
                cursor.execute('''INSERT INTO ports (host_id, port, protocol, state, service, product, version)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)''',
                               (host_id, port_id, protocol, port_state, service, product, version))

                # Parse certificate data from the ssl-cert script output
                ssl_cert = port.find(".//script[@id='ssl-cert']")
                if ssl_cert is not None:
                    issuer = ""
                    subject = ""
                    valid_from = ""
                    valid_until = ""
                    expiration_days = None

                    for table in ssl_cert.findall("table"):
                        if table.attrib.get("key") == "issuer":
                            issuer = "; ".join(f"{elem.attrib['key']}: {elem.text}" for elem in table.findall("elem") if elem.text)
                        elif table.attrib.get("key") == "subject":
                            subject = "; ".join(f"{elem.attrib['key']}: {elem.text}" for elem in table.findall("elem") if elem.text)
                        elif table.attrib.get("key") == "validity":
                            for elem in table.findall("elem"):
                                if elem.attrib.get("key") == "notBefore":
                                    valid_from = elem.text
                                elif elem.attrib.get("key") == "notAfter":
                                    valid_until = elem.text
                                elif elem.attrib.get("key") == "days":
                                    expiration_days = int(elem.text)

                    # Insert certificate data
                    cursor.execute('''INSERT INTO certificates (host_id, port, issuer, subject, valid_from, valid_until, expiration_days)
                                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                   (host_id, port_id, issuer, subject, valid_from, valid_until, expiration_days))

        except AttributeError:
            # Skip if required attributes are missing
            continue

    # Parse WhatWeb data
    for target in root.findall(".//target"):
        try:
            url = target.find("uri").text if target.find("uri") is not None else ""
            if not url:
                continue

            # Extract IP from the plugin named "IP"
            ip = target.find(".//plugin[name='IP']/string").text if target.find(".//plugin[name='IP']/string") is not None else ""

            # Find the corresponding host_id in the hosts table
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            host_row = cursor.fetchone()
            if host_row:
                host_id = host_row[0]

                # Iterate over each plugin to extract its details
                for plugin in target.findall("plugin"):
                    plugin_name = plugin.find("name").text if plugin.find("name") is not None else ""
                    plugin_version = plugin.find("version").text if plugin.find("version") is not None else ""
                    plugin_description = "; ".join([s.text for s in plugin.findall("string")]) if plugin.findall("string") else ""

                    # Insert WhatWeb data into the database
                    cursor.execute('''INSERT INTO whatweb (host_id, url, plugin, version, description)
                                      VALUES (?, ?, ?, ?, ?)''',
                                   (host_id, url, plugin_name, plugin_version, plugin_description))

        except Exception as e:
            # Handle parsing errors gracefully
            print(f"Error parsing WhatWeb data: {e}")
            continue

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Create the database and tables
create_database()

# Create triggers for automatic timestamp updates
create_triggers()

# Parse the final_scan_results.xml file and insert data into the database
parse_xml_to_db("final_scan_results.xml")
