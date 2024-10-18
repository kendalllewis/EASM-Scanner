import xml.etree.ElementTree as ET

def parse_xml_to_db(xml_file):
    # Connect to the SQLite3 database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Iterate through each host in the XML
    for host in root.findall(".//host"):
        try:
            ip = host.find("address").attrib.get("addr", "")
            state = host.find("status").attrib.get("state", "unknown")
            hostname_elem = host.find(".//hostnames/hostname")
            hostname = hostname_elem.attrib.get("name", "") if hostname_elem is not None else ""
            os_elem = host.find(".//os/osmatch")
            os_name = os_elem.attrib.get("name", "unknown") if os_elem is not None else "unknown"

            # Insert host data into the database
            cursor.execute("INSERT INTO hosts (ip, hostname, state, os) VALUES (?, ?, ?, ?)", (ip, hostname, state, os_name))
            host_id = cursor.lastrowid

            # Insert ports data
            for port in host.findall(".//port"):
                port_id = int(port.attrib.get("portid", 0))
                protocol = port.attrib.get("protocol", "tcp")
                port_state = port.find("state").attrib.get("state", "unknown")
                service_elem = port.find("service")
                service = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""

                # Insert port data into the database
                cursor.execute('''INSERT INTO ports (host_id, port, protocol, state, service, product, version)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                                  (host_id, port_id, protocol, port_state, service, product, version))

        except AttributeError as e:
            # Skip the host if required attributes are missing
            print(f"Error processing host: {e}")
            continue

    # Parse WhatWeb results
    for target in root.findall(".//target"):
        try:
            url = target.attrib.get("url", "")
            ip = url.split("/")[2] if "://" in url else url.split("/")[0]

            # Find the corresponding host_id
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            host_row = cursor.fetchone()
            if host_row:
                host_id = host_row[0]

                for plugin in target.findall("plugins/plugin"):
                    plugin_name = plugin.attrib.get("name", "unknown")
                    plugin_version = plugin.attrib.get("version", "unknown")
                    description = plugin.attrib.get("description", "unknown")

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
    print("[+] Data successfully inserted into the database.")
