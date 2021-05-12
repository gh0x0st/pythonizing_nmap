#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os


def main():
    # Protocol Report Lists
    tls_v10_report = []
    tls_v11_report = []
    ssl_v3_report = []

    # Flagged Lists
    flagged_tls_v10 = ''
    flagged_tls_v11 = ''
    flagged_ssl_v3 = ''

    # File Path
    in_path= '/home/tristram/Scans/Stage_5/'

    # Cycle through each XML file
    for file in os.listdir(in_path):
        # Load each XML file
        if file.endswith(".xml"):
            in_xml = os.path.join(in_path, file)
            xml_tree = ET.parse(in_xml)
            xml_root = xml_tree.getroot()
            
            # Cycle through each host
            for host in xml_root.findall('host'):
                ip = host.find('address').get('addr')
                ports_element = host.findall('ports')
                port_element = ports_element[0].findall('port')
                
                # Cycle through each port
                for scanned_port in port_element:
                    port_id = scanned_port.get('portid')
                    script_element = scanned_port.find('script')
                    if script_element:
                        # Cycle through each protocol
                        protocol_element = script_element.findall('table')
                        for tls_protocol in protocol_element: 
                            protocol_version = tls_protocol.attrib['key']
                            
                            # Stage data for TLSv1.0 Table
                            if protocol_version in 'TLSv1.0':
                                flagged_tls_v10 += protocol_version + ','
                            
                            # Stage data for TLSv1.1 Table
                            if protocol_version in 'TLSv1.1':
                                flagged_tls_v11 += protocol_version + ','
                            
                            # Stage data for SSLv3 Table
                            if protocol_version in 'SSLv3':
                                flagged_ssl_v3 += protocol_version + ','

                        # Load TLSv1.0 Data
                        if flagged_tls_v10:
                            flagged_tls_v10 = flagged_tls_v10.strip(',').split(',')
                            tls_v10_report.append([ip,port_id,flagged_tls_v10 ])
                            flagged_tls_v10 = ''
                        
                        # Load TLSv1.1 Data
                        if flagged_tls_v11:
                            flagged_tls_v11 = flagged_tls_v11.strip(',').split(',')
                            tls_v11_report.append([ip,port_id,flagged_tls_v11 ])
                            flagged_tls_v11 = ''
                        
                        # Load SSLv3.0 Data
                        if flagged_ssl_v3:
                            flagged_ssl_v3 = flagged_ssl_v3.strip(',').split(',')
                            ssl_v3_report.append([ip,port_id,flagged_ssl_v3 ])
                            flagged_ssl_v3 = ''


            # CSV Data for TLSv1.0
            with open('detected_tls_v10.csv', 'w') as csvFile:
                writer = csv.writer(csvFile)

                # CSV Headers
                writer.writerow(["IP", "Port", "Protocol"])

                # Cycle through each staged element in list
                for server in tls_v10_report:
                    row_ip = server[0]
                    row_port = server[1]
                    
                    # Write results to row
                    writer.writerow([row_ip,row_port,'TLSv1.0'])

            # CSV Data for TLSv1.1
            with open('detected_tls_v11.csv', 'w') as csvFile:
                writer = csv.writer(csvFile)

                # CSV Headers
                writer.writerow(["IP", "Port", "Protocol"])
                for server in tls_v11_report:
                    row_ip = server[0]
                    row_port = server[1]
                    
                    # Write results to row
                    writer.writerow([row_ip,row_port,'TLSv1.1'])

            # CSV Data for SSLv.3
            with open('detected_ssl_v3.csv', 'w') as csvFile:
                writer = csv.writer(csvFile)

                # CSV Headers
                writer.writerow(["IP", "Port", "Protocol"])
                for server in ssl_v3_report:
                    row_ip = server[0]
                    row_port = server[1]
                    # Write results to row
                    writer.writerow([row_ip,row_port,'SSLv3.0'])

if __name__ == '__main__':
    main()