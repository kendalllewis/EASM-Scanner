import sqlite3

def create_database():
    # Create the SQLite3 database and tables
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create hosts table
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        state TEXT,
                        os TEXT)''')

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
