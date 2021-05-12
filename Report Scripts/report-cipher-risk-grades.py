#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os


def main():
    # Cipher Risk Lists
    ciphers_list = []
    flagged_ciphers = ''

    # Grade Threshold Lists
    high_risk_grades = ['D','E','F']
    moderate_risk_grades = ['C']

    high_risk_ciphers = []
    moderate_risk_ciphers = []

    high_risk_flagged_list = ''
    moderate_risk_flagged_list = ''

    # Path to directory with host XML files
    in_path= '/home/tristram/Downloads/OffSec-master/External/Stage_5/'
    for file in os.listdir(in_path):
        if file.endswith(".xml"):
            # Load XML
            in_xml = os.path.join(in_path, file)
            xml_tree = ET.parse(in_xml)
            xml_root = xml_tree.getroot()

            # Cycle through each host
            for host in xml_root.findall('host'):
                ip = host.find('address').get('addr')
                ports_element = host.findall('ports')
                port_element = ports_element[0].findall('port')
                
                # Cycle through every port
                for scanned_port in port_element:
                    port_id = scanned_port.get('portid')
                    script_element = scanned_port.find('script')
                    if script_element:
                        script_element = script_element.findall('table')    
                        
                        # Cycle through script element
                        for tls_protocol in script_element: 
                            
                            # Cycle through TLS protocol
                            for protocol in tls_protocol:
                                if protocol.attrib.get('key') == 'ciphers':
                                    
                                    # Cycle through each cipher
                                    for entry in protocol:
                                        for en in entry:
                                            if en.attrib.get('key') == 'name':
                                                name = en.text
                                            if en.attrib.get('key') == 'strength':
                                                grade = en.text
                                                # Risk based on grade
                                                if grade in high_risk_grades:
                                                    high_risk_flagged_list += f"{name} ({grade})" + ','
                                                if grade in moderate_risk_grades:
                                                    moderate_risk_flagged_list += f"{name} ({grade})" + ','
                                                
                # Stage flagged data for current host
                if high_risk_flagged_list:    
                    high_risk_flagged_list = list(set(high_risk_flagged_list.strip(',').split(',')))
                    high_risk_ciphers.append([ip,port_id,high_risk_flagged_list])

                if moderate_risk_flagged_list:    
                    moderate_risk_flagged_list = list(set(moderate_risk_flagged_list.strip(',').split(',')))
                    moderate_risk_ciphers.append([ip,port_id,moderate_risk_flagged_list])

                # Reset results for next host
                high_risk_flagged_list = ''
                moderate_risk_flagged_list = ''   

           # Create High Risk Report
            with open('high_risk_tls_ciphers.csv', 'w') as file:
                writer = csv.writer(file)
                
                # CSV Headers
                writer.writerow(["IP", "Port","Cipher Suite"])
                for hrc in high_risk_ciphers:
                    row_ip = hrc[0]
                    row_port = hrc[1]
                    row_cs = '\r\n'.join(hrc[2])

                    # Write results to row
                    writer.writerow([row_ip,row_port,row_cs])

            # Create Moderate Risk Report
            with open('moderate_risk_tls_ciphers.csv', 'w') as file:
                writer = csv.writer(file)
                
                # CSV Headers
                writer.writerow(["IP", "Port","Cipher Suite"])
                for mrc in moderate_risk_ciphers:
                    row_ip = mrc[0]
                    row_port = mrc[1]
                    row_cs = '\r\n'.join(mrc[2])

                    # Write results to row
                    writer.writerow([row_ip,row_port,row_cs])

            
if __name__ == '__main__':
    main()