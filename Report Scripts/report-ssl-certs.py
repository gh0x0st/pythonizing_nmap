#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os
import re


def main():
    # Regular Expressions
    reg_date = r'\d{4}-\d{2}-\d{2}'

    # File Path
    in_path= '/home/tristram/Scans/Stage_6/'

    # Reports
    cert_info_list = ''
    cert_info_report = []

    # Cycle through each XML file
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
                
                # Check Every Port
                for scanned_port in port_element:
                    port_id = scanned_port.get('portid')
                    script_element = scanned_port.find('script')
                    
                    # SSL Cert Top Level
                    if script_element:
                        ssl_element = script_element.findall('table')

                        # Cycle through each certificate
                        for ssl in ssl_element:
                            # Subject Field
                            if ssl.attrib.get('key') == 'subject':
                                for data in ssl:
                                    if data.attrib.get('key') == 'commonName':
                                        host_common_name = data.text
                            # Issuer Field
                            if ssl.attrib.get('key') == 'issuer':
                                for data in ssl:
                                    if data.attrib.get('key') == 'commonName':
                                        issuer_common_name = data.text
                            
                            # Validity Field
                            if ssl.attrib.get('key') == 'validity':
                                for data in ssl:
                                    if data.attrib.get('key') == 'notBefore':
                                        cert_start = data.text
                                        cert_start = re.findall(reg_date, cert_start)[0]
                                    if data.attrib.get('key') == 'notAfter':
                                        cert_end = data.text
                                        cert_end = re.findall(reg_date, cert_end)[0]
                        cert_info_list = f"{ip},{port_id},{host_common_name},{issuer_common_name},{cert_start},{cert_end}"

                # Load Data
                cert_info_list = cert_info_list.split(',')
                cert_info_report.append(cert_info_list)

                # Reset results for next host
                cert_info_list = ''

            # CSV Data
            with open('detected_ssl_certs.csv', 'w') as csvFile:
                writer = csv.writer(csvFile)
                
                # CSV Headers
                writer.writerow(["IP", "Port","CommonName","IssuerCommon","CertStart", "CertEnd"])
                for ci in cert_info_report:
                    if len(ci) == 6:
                        row_ip = ci[0]
                        row_port = ci[1]
                        row_cn = ci[2]
                        row_ion = ci[3]
                        row_cs = ci[4]
                        row_ce = ci[5]
                        # Write results to row
                        writer.writerow([row_ip,row_port,row_cn, row_ion, row_cs, row_ce])


if __name__ == '__main__':
    main()