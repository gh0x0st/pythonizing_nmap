#!/usr/bin/python3

import xml.etree.ElementTree as ET
import subprocess
import shlex
import os
import sys


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


def tcpSynPortScan(target, out_xml,):
    out_xml = os.path.join(out_xml,'65535_portscan.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -p- -n -Pn -sS -T4 --min-parallelism 100 --min-rate 128 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def makeInvokerOwner(path):
    uid = os.environ.get('SUDO_UID')
    gid = os.environ.get('SUDO_GID')
    if uid is not None:
        os.chown(path, int(uid), int(gid))


def is_root():
    if os.geteuid() == 0:
        return True
    else:
        return False


def main():
    if not is_root():
        print('[!] TCP/SYN scans requires root privileges')
        sys.exit(1)
    
    hosts = parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_echo_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_netmask_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_timestamp_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/port_host_discovery.xml')

    target = convertToNmapTarget(hosts)
    tcpSynPortScan(target, os.getcwd())

if __name__ == '__main__':
    main()