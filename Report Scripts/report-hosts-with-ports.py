#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os

def main():
    # Path to directory with host XML files
    in_path = '/home/tristram/Downloads/OffSec-master/External/Stage_3/'

    # CSV Data
    with open('detected_hosts_with_ports.csv', 'w') as file:
        writer = csv.writer(file)

        # CSV Headers
        writer.writerow(['IP', 'Port', 'Service'])
        for file in sorted(os.listdir(in_path)):
            if file.endswith(".xml"):
                if "no_ports.xml" in file:
                    writer.writerow([file.split('_no_ports.xml')[0], 'no-response', 'no-response'])
                else:
                    # Load Service Scan
                    in_xml = os.path.join(in_path, file)
                    xml_tree = ET.parse(in_xml)
                    xml_root = xml_tree.getroot()

                    # Cycle through each host
                    for host in xml_root.findall('host'):
                        ip_once = True
                        ip_address = host.findall('address')[0].attrib['addr']
                        ports_element = host.findall('ports')
                        port_child = ports_element[0].findall('port')
                        open_ports = []

                        # Within each host cycle through the ports
                        for port in port_child:
                            if port.findall('state')[0].attrib['state'] == 'open':
                                port_id = port.attrib['portid']
                                service_name = port.find('service').get('product')
                                if service_name == None:
                                    service_name = port.find('service').get('name')
                                open_ports.append([port_id, service_name])
                        
                        # Within each port cycle through the open ports
                        if len(open_ports):
                            for op in open_ports:
                                # Ensure we only notate the IP once to keep it clean
                                if ip_once == True:
                                    # Write results to row
                                    writer.writerow([ip_address, op[0], op[1]])
                                    ip_once = False
                                else:
                                    # Write results to row
                                    writer.writerow([None, op[0], op[1]])
                        else:
                            # Write results to row if none
                            writer.writerow([ip_address, 'none', 'none'])

if __name__ == '__main__':
    main()