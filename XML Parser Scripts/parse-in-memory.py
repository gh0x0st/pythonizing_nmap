#!/usr/bin/python3

import xml.etree.ElementTree as ET
import subprocess
import shlex


def nmapMemory(target):
    args = shlex.split(f"/usr/bin/nmap {target} -T4 -Pn -n -vv -sS -min-parallelism 100 --min-rate 64 --top-ports 1000 -oX -")
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def parseDiscoverPortsMemory(in_xml):
    results = []
    port_list = ''
    #xml_tree = ET.parse(in_xml)
    #xml_root = xml_tree.getroot() 
    xml_root = ET.fromstring(in_xml.decode('utf-8'))
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
    target = '127.0.0.1'
    xml_output = nmapMemory(target)[0]

    targets = parseDiscoverPortsMemory(xml_output)
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Scanning: {target_ip} against ports {target_ports}')    


if __name__ == '__main__':
    main()
