#!/usr/bin/python3

import xml.etree.ElementTree as ET

def parseDiscoverPorts(in_xml):
    results = []
    port_list = ''
    xml_tree = ET.parse(in_xml)
    xml_root = xml_tree.getroot()
    for host in xml_root.findall('host'):
        ip = host.find('address').get('addr')
        ports = host.findall('ports')[0].findall('port')
        for port in ports:
            state = port.find('state').get('state')
            if state == 'open':
                port_list += port.get('portid') + ','
        port_list = port_list.rstrip(',')
        if port_list:
            results.append(f"{ip} {port_list}")
        port_list = ''
    return results


def main():
    targets = parseDiscoverPorts('/home/tristram/Downloads/OffSec-master/External/Stage_2/syn_port_scan.xml')
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Nmap Format Example: nmap {target_ip} -p {target_ports}')

if __name__ == '__main__':
    main()
