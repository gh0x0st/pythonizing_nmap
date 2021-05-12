#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os


def main():
    # Cipher Risk Lists
    ciphers_list = []
    flagged_ciphers = ''

    # Static Key Ciphers
    static_key_list = ['TLS_RSA_WITH_DES_CBC_SHA', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_anon_WITH_RC4_128_SHA', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA', 'TLS_DH_anon_WITH_DES_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'TLS_RSA_WITH_SEED_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_WITH_NULL_MD5', 'TLS_DH_anon_WITH_RC4_128_MD5', 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'TLS_RSA_WITH_NULL_SHA', 'TLS_DH_anon_WITH_SEED_CBC_SHA', 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_IDEA_CBC_SHA', 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_128_CBC_SHA256', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA', 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', 
                      'TLS_RSA_WITH_AES_256_CBC_SHA256', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5']

    # Path to directory with host XML files
    in_path= '/home/tristram/Scans/Stage_5/'
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
                                                # Check for targeted cipher
                                                if name in static_key_list:
                                                    flagged_ciphers += name + ','
                                                
                # Stage flagged data for current host
                if flagged_ciphers:    
                    flagged_ciphers = list(set(flagged_ciphers.strip(',').split(',')))
                    ciphers_list.append([ip,port_id,flagged_ciphers])

                # Reset results for next host
                flagged_ciphers = ''

            # Create NULL Cipher Report
            with open('detected_static_key_ciphers.csv', 'w') as file:
                writer = csv.writer(file)
                
                # CSV Headers
                writer.writerow(["IP", "Port","Cipher Suite"])
                for entry in ciphers_list:
                    row_ip = entry[0]
                    row_port = entry[1]
                    row_cs = '\r\n'.join(entry[2])
                
                    # Write results to row
                    writer.writerow([row_ip,row_port,row_cs])

            
if __name__ == '__main__':
    main()