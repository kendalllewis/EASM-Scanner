import sqlite3
import json

def export_to_json():
    # Connect to the database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Get total number of hosts
    cursor.execute("SELECT COUNT(*) FROM hosts")
    total_hosts = cursor.fetchone()[0]

    # Get total number of ports
    cursor.execute("SELECT COUNT(*) FROM ports")
    total_ports = cursor.fetchone()[0]

    # Get number of ports per host
    cursor.execute("SELECT ip, COUNT(*) as port_count FROM ports INNER JOIN hosts ON hosts.id = ports.host_id GROUP BY ip")
    ports_per_host = [{"ip": row[0], "port_count": row[1]} for row in cursor.fetchall()]

    # Get HTTP details for hosts
    cursor.execute("SELECT ip, port, service, product, version FROM ports INNER JOIN hosts ON hosts.id = ports.host_id WHERE service = 'http'")
    http_details = [{"ip": row[0], "port": row[1], "service": row[2], "product": row[3], "version": row[4]} for row in cursor.fetchall()]

    # Get open services by type
    cursor.execute("SELECT service, COUNT(*) FROM ports WHERE state = 'open' GROUP BY service")
    service_counts = [{"service": row[0], "count": row[1]} for row in cursor.fetchall()]

    # Create a JSON object with all the gathered data
    data = {
        "total_hosts": total_hosts,
        "total_ports": total_ports,
        "ports_per_host": ports_per_host,
        "http_details": http_details,
        "service_counts": service_counts
    }

    # Write the JSON data to a file
    with open("scan_results.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    conn.close()
    print("[+] Data exported to scan_results.json")

# Export the data to JSON
export_to_json()

