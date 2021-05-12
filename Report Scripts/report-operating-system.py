#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv

def main():
    # Path top the os scan file
    in_xml = '/home/tristram/Scans/Stage_4/osdetection.xml'

    # CSV Data
    with open('detected_hosts_os.csv', 'w') as file:
        writer = csv.writer(file)
        # CSV Headers
        writer.writerow(['IP', 'OperatingSystem'])

        # Load OS Scan XML
        xml_tree = ET.parse(in_xml)
        xml_root = xml_tree.getroot()

        # Cycle through each host
        for host in xml_root.findall('host'):
            ip_address = host.findall('address')[0].attrib['addr']
            try:
                os_element = host.findall('os')
                os_name = os_element[0].findall('osmatch')[0].attrib['name']
            except IndexError:
                os_name = 'Unknown'
            
            # Write results to row
            writer.writerow([ip_address, os_name])
            

if __name__ == '__main__':
    main()