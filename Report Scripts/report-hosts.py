#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv

def main():
    # File Paths
    in_xml_port = '/home/tristram/Scans/Stage_1/tcp_syn_host_discovery.xml'
    in_xml_echo = '/home/tristram/Scans/Stage_1/icmp_echo_host_discovery.xml'
    in_xml_netmask = '/home/tristram/Scans/Stage_1/icmp_netmask_host_discovery.xml'
    in_xml_timestamp = '/home/tristram/Scans/Stage_1/icmp_timestamp_host_discovery.xml'

    # Load Port XML
    xml_tree_port = ET.parse(in_xml_port)
    xml_root_port = xml_tree_port.getroot()

    # Load ICMP Echo XML
    xml_tree_echo = ET.parse(in_xml_echo)
    xml_root_echo = xml_tree_echo.getroot()

    # Load ICMP Netmask XML
    xml_tree_netmask = ET.parse(in_xml_netmask)
    xml_root_netmask = xml_tree_netmask.getroot()

    # Load ICMP Timestamp XML
    xml_tree_timestamp = ET.parse(in_xml_timestamp)
    xml_root_timestamp = xml_tree_timestamp.getroot()

    # CSV File
    with open('detected_hosts.csv', 'w') as file:
        writer = csv.writer(file)
        # CSV Headers
        writer.writerow(['IP', 'Status', 'ICMP Echo', 'ICMP Netmask', 'ICMP Timestamp', 'Port'])

        # Load SYN Port XML
        for host in xml_root_port.findall('host'):
            host_status = 'down'
            master_ip = host.find('address').get('addr')
            port_state = host.find('status').get('state')
            port_reason = host.find('status').get('reason')

            # Load ICMP Echo XML
            for host in xml_root_echo.findall('host'):
                echo_ip = host.find('address').get('addr')
                echo_state = host.find('status').get('state')
                echo_reason = host.find('status').get('reason')
                
                # Load ICMP Netmask
                if master_ip == echo_ip:
                    for host in xml_root_netmask.findall('host'):
                        netmask_ip = host.find('address').get('addr')
                        netmask_state = host.find('status').get('state')
                        netmask_reason = host.find('status').get('reason')
                        
                        # Load ICMP Timestamp
                        if master_ip == netmask_ip: 
                            for host in xml_root_timestamp.findall('host'):
                                timestamp_ip = host.find('address').get('addr')
                                timestamp_state = host.find('status').get('state')
                                timestamp_reason = host.find('status').get('reason')
                                if master_ip == timestamp_ip:
                                    if port_state == 'up' or echo_state == 'up' or netmask_state == 'up' or timestamp_state == 'up':
                                        host_status = 'up'
                                    
                                    # Write results to row
                                    writer.writerow([master_ip, host_status, echo_reason, netmask_reason, timestamp_reason, port_reason])

if __name__ == '__main__':
    main()