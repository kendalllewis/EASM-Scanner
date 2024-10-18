import json

def export_to_json():
    # Connect to the database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Get total number of hosts
    cursor.execute("SELECT COUNT(*) FROM hosts")
    total_hosts = cursor.fetchone()[0]

    # Get total number of open ports
    cursor.execute("SELECT COUNT(*) FROM ports WHERE state='open'")
    open_ports = cursor.fetchone()[0]

    # Get unique open ports
    cursor.execute("SELECT DISTINCT port FROM ports WHERE state='open'")
    unique_ports = [row[0] for row in cursor.fetchall()]

    # Get operating systems with IP addresses
    cursor.execute("SELECT ip, os FROM hosts")
    operating_systems = [{"ip": row[0], "os": row[1]} for row in cursor.fetchall()]

    # Get services list
    cursor.execute("SELECT ip, port, service, product, version FROM ports INNER JOIN hosts ON ports.host_id = hosts.id")
    services = [{"ip": row[0], "port": row[1], "service": row[2], "product": row[3], "version": row[4]} for row in cursor.fetchall()]

    # Get WhatWeb results
    cursor.execute("SELECT ip, url, plugin, version, description FROM whatweb INNER JOIN hosts ON whatweb.host_id = hosts.id")
    whatweb_results = [{"ip": row[0], "url": row[1], "plugin": row[2], "version": row[3], "description": row[4]} for row in cursor.fetchall()]

    # Create JSON data structure
    data = {
        "total_hosts": total_hosts,
        "open_ports": open_ports,
        "unique_ports": unique_ports,
        "operating_systems": operating_systems,
        "services": services,
        "whatweb_results": whatweb_results
    }

    # Save to JSON file
    with open("scan_results.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    conn.close()
    print("[+] JSON export completed: scan_results.json")

