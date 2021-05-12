#!/usr/bin/python3

import sqlite3

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
    return conn


def select_content(conn):
    sql = """SELECT IP 
              FROM HostDiscovery 
              WHERE Status = 'up' 
              """
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows


def main():
    db_file = 'PythonizingNmap.db'
    conn = create_connection(db_file)
    live_hosts = select_content(conn)
    for host in live_hosts:
        print(f'Live: {host[0]}')


if __name__ == '__main__':
    main()