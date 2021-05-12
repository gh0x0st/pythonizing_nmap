#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv

def main():
    # Path to directory with host XML files
    in_xml = '/home/tristram/Scans/Stage_2/top_1000_portscan.xml'

    # CSV Data
    with open('detected_hosts_no_ports.csv', 'w') as file:
        writer = csv.writer(file)

        # CSV Headers
        writer.writerow(['IP', 'Port', 'Service'])

        # Load Top 1000 Port Scan
        xml_tree = ET.parse(in_xml)
        xml_root = xml_tree.getroot()
        
        # Cycle through each host
        for host in xml_root.findall('host'):
            ip_address = host.findall('address')[0].attrib['addr']
            ports_element = host.findall('ports')
            port_child = ports_element[0].findall('port')
            open_ports = []

            # Within each host cycle through the ports
            for port in port_child:
                if port.findall('state')[0].attrib['state'] == 'open':
                    port_id = port.attrib['portid']
                    open_ports.append(port_id)

            # Write results to row
            if len(open_ports) == 0:
                writer.writerow([ip_address, 'no-response', 'no-response'])


if __name__ == '__main__':
    main()