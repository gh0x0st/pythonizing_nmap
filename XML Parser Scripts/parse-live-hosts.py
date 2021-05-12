#!/usr/bin/python3

import xml.etree.ElementTree as ET

def parseDiscoverXml(in_xml):
    live_hosts = []
    xml_tree = ET.parse(in_xml)
    xml_root = xml_tree.getroot()
    for host in xml_root.findall('host'):
        ip_state = host.find('status').get('state')
        if ip_state == "up":
            live_hosts.append(host.find('address').get('addr'))
    return live_hosts


def convertToNmapTarget(hosts):
    hosts = list(dict.fromkeys(hosts))
    return " ".join(hosts)


def main():
    hosts = parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_echo_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_netmask_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_timestamp_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/tcp_syn_host_discovery.xml')

    print(f"Flagged Hosts: {len(hosts)}")
    print(f"Unique Hosts: {len(list(dict.fromkeys(hosts)))}")
    print(f"Nmap Format Example: {convertToNmapTarget(hosts)}")

if __name__ == '__main__':
    main()
