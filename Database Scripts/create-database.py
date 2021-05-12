#!/usr/bin/python3

import sqlite3

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
    return conn


def create_db(conn):
    createHostDiscoveryTable="""CREATE TABLE IF NOT EXISTS HostDiscovery (
            id integer PRIMARY KEY,
            IP text NOT NULL,
            Status text NOT NULL,
            ICMP_Echo text NOT NULL);"""
    try:
        c = conn.cursor()
        c.execute(createHostDiscoveryTable)
    except Exception as e:
        print(e)


def main():
    db_file = 'PythonizingNmap.db'
    conn = create_connection(db_file)
    create_db(conn)


if __name__ == '__main__':
    main()