#!/usr/bin/python3

import xml.etree.ElementTree as ET
import subprocess
import shlex
import os


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


def serviceScan(target_ip, target_ports, out_xml):
    out_xml = os.path.join(out_xml,f'{target_ip}_services.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} -n -Pn -sV --version-intensity 6 --script banner -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def main():
    in_xml = '/home/tristram/Scans/Stage_2/top_1000_portscan.xml'
    targets = parseDiscoverPorts(in_xml)
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Scanning: {target_ip} against ports {target_ports}')
        serviceScan(target_ip, target_ports, os.getcwd())
        

if __name__ == '__main__':
    main()
