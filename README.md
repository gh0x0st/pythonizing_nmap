# Pythonizing Nmap
When I started to get into this field, I tried my best to stick to manual workflows to get the lay of the land. As time passed by and I gained more experience the more I found that I needed to find better ways to be more efficient with my time. One place where I spent too much time was performing my initial enumeration with Nmap on larger scale assessments, staying organized as well as writing reports with the information I have collected. 

I believe that automation is crucial for some aspects of a penetration test and Python is a tool to help us facilitate this. Allow me to show you various ways you can enhance your workflows by incorporating Python into your Nmap processes.

## Boots on The Ground

1. Opening Remarks on Nmap Wrappers
2. Using Subprocess with Nmap
3. Parsing Nmap XML
4. Importing Nmap XML into SQLite Databases
5. Python Nmap Wrapper Scripts
6. Generating Reports from Nmap XML
7. Wrapping Up

## Opening Remarks on Nmap Wrappers

Keep in mind that there is no one size fits all when it comes to Nmap scans. Before you run any sort of Nmap wrapper you should always look at the parameters that are in play and craft them to meet your needs and applicable scenarios. For your convenience here are the individual nmap commands I have incorporated in these scripts. 

I like to keep the structure of my nmap commands consistent in a TARGET PORT OMIT SCAN SPEED VERBOSITY OUTPUT format.

| Stage | Nmap Command | Requires Root
| -------------- | :--------- | :--------- | 
| Host Discovery - ICMP Echo | nmap TARGET -n -sn -PE -vv -oX OUTPUT | Yes
| Host Discovery - ICMP Netmask | nmap TARGET -n -sn -PM -vv -oX OUTPUT | Yes
| Host Discovery - ICMP Timestamp | nmap TARGET -n -sn -PP -vv -oX OUTPUT | Yes
| Host Discovery - Port Scanning | nmap TARGET -PS21,22,23,25,80,113,443 -PA80,113,443 -n -sn -T4 -vv -oX OUTPUT | Yes
| Port Scanning (Top 1000) | nmap TARGET --top-ports 1000 -n -Pn -sS -T4 --min-parallelism 100 --min-rate 64 -vv -oX OUTPUT | Yes
| Service Detection | nmap TARGET -p PORTS -n -Pn -sV --version-intensity 6 --script banner -T4 -vv -oX OUTPUT | No
| OS Detection | nmap TARGET -n -Pn -O -T4 --min-parallelism 100 --min-rate 64 -vv -oX OUTPUT | Yes
| SSL Ciphers | nmap TARGET -p PORTS -n -Pn --script ssl-enum-ciphers -T4 -vv -oX OUTPUT | No
| SSL Certs | nmap TARGET -p PORTS -n -Pn --script ssl-cert -T4 -vv -oX OUTPUT | No
| Port Scanning (1-65535) | nmap TARGET -p- -n -Pn -sS -T4 --min-parallelism 100 --min-rate 128 -vv -oX OUTPUT | Yes

## Using Subprocess with Nmap

The `subprocess` (https://docs.python.org/3/library/subprocess.html) library allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. This library will make it easy for us to make calls to Nmap as well as manage the output effectively. Because we are going to use `subprocess` to call a program with parameters, we must pass our arguments as a list. What makes this tricky is each parameter will need to be its own element. However, Python makes this easy for us by using the `shlex` (https://docs.python.org/3/library/shlex.html) library. 

This library takes in a string and it will split each space delimiter parameter as its own element in the list. I frequently see scripts do this manually but it's not necessary. There may be some reading this and wonder why we are using a library when we can just use the built-in `split()` method from a string. These two approaches do nearly the same thing. The difference being is the `split()` method will create a list based on the delimiter and `shlex.split()` will create a delimited list intelligently based on how the shell interprets the input. 

What this means is if you have any parameters passed to Nmap that contains spaces within quotes, then `split()` will break your input when delimiting on spaces whereas `shlex.split()` will break it down appropriately. In a nut shell, if you do not plan on using spaces where you shouldn't, `split()` will work just fine, but out of my own habit, I incorporate `shlex.split()` to build my arguments for `subprocess`. 

You can see an example of what this looks like below:

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/shlex-vs-split.png?raw=true "shlex-vs-split")

Reading STDOUT and STDERR is also relatively easy to do if you care about capturing both within your scripts. You can declare the values of the stdout/stderr arguments as `subprocess.PIPE`. Finally, you can read the data passed from stdout and stderr by using `communicate()` and declare them in variables respectively.

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/subprocess-stdout-stderr.png?raw=true "subprocess-stdout-stderr")

I invite you to look at the man page for subprocess to see if there's any other tricks that you could find useful as it expands a lot further than what I have provided here.

https://docs.python.org/3/library/subprocess.html#subprocess.Popen.communicate

## Parsing Nmap XML 

One of my favorite features of Nmap is the ability to output our scan results to XML files. This enables us to parse through them to generate reports or use the output to generate input parameters for other Nmap operations. Let's look at an example of the XML output:

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/xml-parse-sample.png?raw=true "xml-parse-sample")

### Parse for Live Hosts

The first case where this will be useful for us is to determine which hosts from our host discovery probes are considered up. To facilitate this task in python we'll take advantage of the `xml.etree.ElementTree` (https://docs.python.org/3/library/xml.etree.elementtree.html) library. Take a look at the note in https://github.com/gh0x0st/pythonizing_nmap/blob/main/XML%20Parser%20Scripts/README.md for an alternate library if you do not free comfortble with using ElementTree.

Our helper function will take in the path of an XML file we designate and parse out the hosts that are flagged as being 'up'. 

Since I use all possible discovery probes I use `parseDiscoverXml()` to take in the results from all the Xml files, then I use a second helper function to remove any duplicates and output them space delimited so I can use those at the target input values for future Nmap calls.

```Python
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
```

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/parse-live-hosts.png?raw=true "parse-live-hosts")

### Parse for Accessible Ports

Now that we have a way to easily construct a list of available hosts, we can move onto port scanning. After this operation is finished, we'll need a way to programmatically parse the ports that considered available to our attacker machine. Our port scanning stages scripts will produce files called `top_1000_portscan.xml` / `full_portscan.xml` respectively. 

What we will do with this file is parse through every host in the `hosts` element and for each host we will loop through every port in the `ports` element. After it flags a port that's found to be open it'll keep all the results in a list with each element in a "<IP> <PORT>,<PORT>" format. When we start our service scanning, we'll split the results so we can designate our target host and target hosts respectively in future Nmap calls. This allows to programmatically generate our Nmap commands with the necessary target ip addresses and ports.
    
```Python
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
    targets = parseDiscoverPorts('/home/tristram/Scans/Stage_2/top_1000_portscan.xml')
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Nmap Format Example: nmap {target_ip} -p {target_ports}')

if __name__ == '__main__':
    main()  
```

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/parse-accessible-ports.png?raw=true "parse-accessible-ports")

### Parsing XML in Memory

The previous examples showed you how you can parse XML files that are on disk, but you are also able to parse XML without relying on XML on disk by changing a few approaches. Specifically, we'll tell Nmap to output XML to stdout and we will store that in a variable. The output itself will be stored in the first element in the `tuple` as a `bytes-like object`. We will just need to make a few changes but can borrow nearly the entire function we created before.

The only changes we need to make will be to remove `ET.parse` and `xml_tree.getroot()` and replace with `ET.fromstring`  which parses XML from a string directly into an Element, which is the root element of the parsed tree.

Personally, I do not use this approach as much as I like to have the XML files on disk so I can use with other operations. Keep in mind that if you wanted to write your tool that works with everything in memory then you should keep an eye on your system resources. Some Nmap scans can produce quite large output files and you do not want to bog down your system or lose data in the event of a system crash.

```PYTHON
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
```

## Importing Nmap XML into SQLite Databases

Since we have learned previously how to parse Nmap XML using Python we can also take those results and import them into SQLite Databases. From there you could use that database to build input parameters, generate reports or keep historical information from past engagements. The `sqlite3` (https://docs.python.org/3/library/sqlite3.html) library does virtually all the hard work for us. Keep in mind that this library requires us to work with `tuples` when you receive results back from the database. They work just like lists except you cannot change the element values. 

Let's look at how this can be done with a simple use case scenario for storing the results from a host discovery scan and whether an IP is up or not based on the results from an ICMP Echo scan.

1. Creating the Database File
2. Inserting Data into a Table
3. Selecting Content from a Table

### Creating the Database File

This is where we'll create the actual database file on disk. Within the create_db function you can setup your tables and the values you want to store. If you want some ideas on what sort of tables could work for you then consider peaking at section 6 of this post before moving on as those sections produce CSV tables with various amounts of information.

```PYTHON
#!/usr/bin/python3

import sqlite3

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
    return conn


def create_db(conn):
    createHostDiscoveryTable="""CREATE TABLE IF NOT EXISTS HostDiscovery (
            id integer PRIMARY KEY,
            IP text NOT NULL,
            Status text NOT NULL,
            ICMP_Echo text NOT NULL);"""
    try:
        c = conn.cursor()
        c.execute(createHostDiscoveryTable)
    except Exception as e:
        print(e)


def main():
    db_file = 'PythonizingNmap.db'
    conn = create_connection(db_file)
    create_db(conn)


if __name__ == '__main__':
    main()
```

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/create-database.png?raw=true "create-database")

### Inserting Data into a Table

Now that our table is created, we can define our insert_content function to insert our parsed XML data directly into the `HostDiscovery` table. Granted I hardcoded some values here this would be a good function to parameterize to make it more dynamic. Keep note that we are inserting our data as a `tuple`.

```PYTHON
#!/usr/bin/python3

import sqlite3
import xml.etree.ElementTree as ET


def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
    return conn


def insert_content(conn, content):
    sql = ''' INSERT INTO HostDiscovery(IP,Status,ICMP_Echo)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, content)
    return cur.lastrowid


def main():
    # Database Connection
    db_file = 'PythonizingNmap.db'
    conn = create_connection(db_file)

    # Parse XML
    in_xml_echo = '/home/tristram/Scans/Stage_1/icmp_echo_host_discovery.xml'

    # Load ICMP Echo XML
    xml_tree_echo = ET.parse(in_xml_echo)
    xml_root_echo = xml_tree_echo.getroot()

    # Load ICMP Echo XML
    for host in xml_root_echo.findall('host'):
        echo_ip = host.find('address').get('addr')
        echo_state = host.find('status').get('state')
        echo_reason = host.find('status').get('reason')
        
        # Insert results into database
        insert_content(conn, (echo_ip, echo_state, echo_reason))
        conn.commit()


if __name__ == '__main__':
    main()
```

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/insert-content.png?raw=true "insert-content")

### Selecting Content from a Table

After our data is inserted into the database what you can do from here is up to you! You could use this to store results from past engagements or even use it as a working database where you can build other automated workflows that utilize information selected from the database itself. In this example here we are selecting all the hosts that are considered 'up'.

```PYTHON
#!/usr/bin/python3

import sqlite3

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
    return conn


def select_content(conn):
    sql = """SELECT IP 
              FROM HostDiscovery 
              WHERE Status = 'up' 
              """
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows


def main():
    db_file = 'PythonizingNmap.db'
    conn = create_connection(db_file)
    live_hosts = select_content(conn)
    for host in live_hosts:
        print(f'Live: {host[0]}')


if __name__ == '__main__':
    main()
```

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/select-content.png?raw=true "select-content")

## Python Nmap Wrapper Scripts

Now that we've gone through parsing the XML files from Nmap we can use this approach to programmatically generate input parameters for other Nmap operations where we need to designate target IPs and/or ports. I have included below some thoughts around a staged approach to Nmap enumeration. Keep in mind that the code snippets provided are intended to act as blueprints for you to build upon. 

As you read these examples you will find cases where we scan individual IPs at a time, resulting in multiple XML output files and others where I have a single scan targeting all the IPs resulting in a single XML output file. I did this intentionally for you to weight the benefits of parsing through individual XML files vs a single XML file. One option allows you to pass in a single file into your functions where the others require you use a for loop. If you use individually XML files it would be easier to review the results for a specific machine vs picking out the bits you want a in a larger file.

### Stage 1 - Host Discovery

With this step the objective is to determine whether something exists at a particular IP based on the response to your probes. You'll typically encounter straight ICMP restrictions at the firewall, but there are cases where there's misconfigurations or even intended configurations where specific ICMP types are permitted. Because of this I like to take advantage of `ICMP ECHO`, `ICMP TIMESTAMP` and `ICMP NETMASK` probes by sending them individually.

Outside of ICMP probes, another approach you will likely have to take is to run a port scan with a small subset of ports to solicit a response from the firewall. In these cases, a `RESET` or `SYN-ACK` from the firewall denotes a live host at that IP address. I combine both half open scans and ack scans (https://nmap.org/book/host-discovery-strategies.html) with a very small subset of ports to try. By combining all five of these probes together you can craft yourself a scripted host discovery solution to enhance your chances of discovering a live host.

Granted during this stage all you want is to know is whether a host is up. However, I like to expand on this a little more by reporting how each host responds to each of the probes. You may identify hosts that allow ICMP and if the client believes they are blocking ICMP across the board from the internet it could be helpful for them to be aware.

```PYTHON
#!/usr/bin/python3

import shlex
import subprocess
import os
import sys


def sendIcmpEcho(target, out_xml):
    out_xml = os.path.join(out_xml,'icmp_echo_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"                     
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def sendIcmpNetmask(target, out_xml):
    out_xml = os.path.join(out_xml,'icmp_netmask_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -n -sn -PM -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def sendIcmpTimestamp(target, out_xml):
    out_xml = os.path.join(out_xml,'icmp_timestamp_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -n -sn -PP -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def sendTcpSyn(target, out_xml):
    out_xml = os.path.join(out_xml,'tcp_syn_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -PS21,22,23,25,80,113,443 -PA80,113,443 -n -sn -T4 -vv -oX {out_xml}"
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
        print('[!] The discovery probes in this script requires root privileges')
        sys.exit(1)
    
    target = '127.0.0.1'

    sendIcmpEcho(target, os.getcwd())
    sendIcmpNetmask(target, os.getcwd())
    sendIcmpTimestamp(target, os.getcwd())
    sendTcpSyn(target, os.getcwd())

if __name__ == '__main__':
    main()
```

### Stage 2 - Port Scanning (Top 1000)

I do not find services running on non-standard ports too often in production. Because of this I focus on the ports that have a higher ratio as defined in the nmap-services file. This will help save you time while finding the ports that are likely to be accessible. Based on the nmap author's research (https://nmap.org/book/performance-port-selection.html), scanning the top 1000 ports will catch roughly 93% of the TCP ports. The statistics here are in your favor and you'll find most of the ports within a reasonable amount of time. 

```PYTHON
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
    out_xml = os.path.join(out_xml,'top_1000_portscan.xml')
    nmap_cmd = f"/usr/bin/nmap {target} --top-ports 1000 -n -Pn -sS -T4 --min-parallelism 100 --min-rate 64 -vv -oX {out_xml}"
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
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/tcp_syn_host_discovery.xml')

    target = convertToNmapTarget(hosts)
    tcpSynPortScan(target, os.getcwd())

if __name__ == '__main__':
    main()
```

### Stage 3 - Service Detection

Service scanning is something that will catch inexperienced pen testers off guard when they discover that a simple service scan, they run all the time on CTFs just alerted a blue team to their presence an hour in on their assessment. Allow me to provide you an example of what I’m talking about and look at an example from the nmap-service-probes file:

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/nmap-service-probes.png?raw=true "nmap-service-probes")

If you come across any server that uses ports 515,1028,1068,1503,1720,1935,2040,3388,3389 then nmap, with the default options, will eventually use the TerminalServer probes. Here's the problem. If you have a client that uses a Cisco IPS for example that sits in front of that server and it sees `\x03\0\0\x0b\x06\xe0\0\0\0\0\0|` destined to any port that isn't 3389, then it's going to flag you thinking you're trying to connect to RDP on a non-standard port. Because of this as a rule of thumb I put a hard stop on letting nmap try to service probe anything on those ports so I block those off the bat in the config file on line 29 `Exclude T:9100-9107,T:515,T:1028,T:1068,T:1503,T:1720,T:1935,T:2040,T:3388`.

_NOTE: There is a `--exclude-ports` parameter but I like to show people that there are configurable options within the config files_

The problem doesn't stop there though. If you run into a port that nmap cannot figure out, it will try every possible probe up the intensity level, which by default is 7 (https://nmap.org/book/man-version-detection.html). If you look at the snippet below, there is another terminal server probe that is set to rarity 7, so those probes would be included. To prevent that from happening, I set my intensity version to 5 or 6 via `--version-intensity` depending on how paranoid I am.

If you have access to lab network with some sort of IDS/IPS it would be great practice for you to see what type of scans trigger alerts and what you can do to prevent them from happening.

![Alt text](https://github.com/gh0x0st/pythonizing_nmap/blob/main/Screenshots/nmap-service-probes-2.png?raw=true "nmap-service-probes-2")

```PYTHON
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
```

### Stage 4 - OS Detection

I'm a bit torn on using the OS discovery scan over the internet. Sometimes it does not provide me anything useful and other times it provides me a gold mine with unsupported operating systems. I will run this scan just to see and will try to verify through other types of enumeration, such as identifying os requirements for the running software if I'm able. If I'm on the network probing a device, I'll typically use this all the time if I'm on the internal network but over the internet it all depends on if I have anything else to work off from first.

```PYTHON
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


def osScan(targets, out_xml):
    out_xml = os.path.join(out_xml,f'osdetection.xml')
    nmap_cmd = f"/usr/bin/nmap {targets} -n -Pn -O -T4 --min-parallelism 100 --min-rate 64 -vv -oX {out_xml}"
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
        print('[!] TCP/IP fingerprinting (for OS scan) requires root privileges.')
        sys.exit(1)
    
    hosts = parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_echo_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_netmask_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/icmp_timestamp_host_discovery.xml')
    hosts += parseDiscoverXml('/home/tristram/Scans/Stage_1/port_host_discovery.xml')

    target = convertToNmapTarget(hosts)

    osScan(target, os.getcwd())
        

if __name__ == '__main__':
    main()
```

### Stage 5 - SSL Ciphers

For the most part I try to keep NSE scripts for more targeted enumeration, apart from `ssl-enum-ciphers` and `ssl-certs`. The NSE script `ssl-enum-ciphers` is particularly useful for when your target under regulatory requirements and aren't supposed to be using unsafe TLS configurations. Some of the NSE scripts can be noisy so weigh the benefit of what you are trying to learn about a target vs the risk of being busted. 

The results of this NSE script exports nicely into XML and I'll show you how you can convert these results into a CSV format so you can easily move into a report further down.

```PYTHON
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


def sslCipherScan(target_ip, target_ports, out_xml):
    out_xml = os.path.join(out_xml,f'{target_ip}_ssl_ciphers.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} -n -Pn --script ssl-enum-ciphers -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def main():
    in_xml = '/home/tristram/Scans/Stage_2/syn_port_scan.xml'
    targets = parseDiscoverPorts(in_xml)
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Scanning: {target_ip} against ports {target_ports}')
        sslCipherScan(target_ip, target_ports, os.getcwd())
        

if __name__ == '__main__':
    main()
```

### Stage 6 - SSL Certs

I like to include this step because from time to time misconfigured or poorly crafted SSL certificates can reveal quite a bit of information. For example, if you identify a web server that's accessible to the internet and it has a certificate signed by an internal CA then there is a good chance that web server is behind reverse proxy or a server on the private network being NAT'd to the internet which could lead to a damaging foothold if you can identify an exploitable condition.

```PYTHON
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


def sslCertScan(target_ip, target_ports, out_xml):
    out_xml = os.path.join(out_xml,f'{target_ip}_ssl_certs.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} -n -Pn --script ssl-cert -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def main():
    in_xml = '/home/tristram/Scans/Stage_2/syn_port_scan.xml'
    targets = parseDiscoverPorts(in_xml)
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Scanning: {target_ip} against ports {target_ports}')
        sslCertScan(target_ip, target_ports, os.getcwd())
        

if __name__ == '__main__':
    main()
```

### Stage 7 - Port Scanning (1-65535)

I intentionally run this step last because it takes a long time if you have a lot of hosts. Based on the stats from the first port scan we'll only have a 7% chance of finding anything new so the return on investment of is particularly low. However, this stage is still something worth digging into a little bit. Obviously, we want our scans to run as fast as possible but we're too noisy we might trip an alarm, especially since we're scanning the entire TCP port range. 

If you have a lot of time to spare, consider the low and slow approach. If you're not concerned about alerts, then play around with the timing and performance parameters (https://nmap.org/book/man-performance.html). I've found `--min-parallelism 100 --min-rate 128` to be a good sweet spot between speed and reliably.

```PYTHON
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
```

## Generating Reports from Nmap XML

Depending on the size of your engagement the process of transcribing your notes into a report can be quite tedious. Thankfully this is another place where Python comes to the rescue. We can take the same XML files we were working with before to generate CSV files that we can then use to import into the report format of our choosing. 

The scripts for this can be a little confusing with the all the loops so I added comments to help describe each step. Keep a mental note that if there are multiple tables shown in a section that means that script will create that many tables.

### Detected Hosts

| IP | Status | ICMP Echo | ICMP Netmask | ICMP Timestamp | Port
| :--- | :---| :---| :---| :---| :---| 
| 192.168.0.100|down|no-response|no-response|no-response|no-response
| 192.168.0.101|up|echo-reply|no-response|timestamp-reply|reset
| 192.168.0.102|up|echo-reply|no-response|no-response|syn-ack
| 192.168.0.103|down|no-response|no-response|no-response|no-response

```PYTHON
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
```

### Detected Hosts Without Ports

| IP | Port| Service
| :--- | :---| :---|
| 192.168.0.104|no-response|no-response|no-response
| 192.168.0.105|no-response|no-response|no-response
| 192.168.0.106|no-response|no-response|no-response
| 192.168.0.107|no-response|no-response|no-response

```PYTHON
#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv

def main():
    # Path to directory with host XML files
    in_xml = '/home/tristram/Scans/Stage_2/top_1000_portscan.xml'

    # CSV Data
    with open('detected_hosts_no_ports.csv', 'w') as file:
        writer = csv.writer(file)

        # CSV Headers
        writer.writerow(['IP', 'Port', 'Service'])

        # Load Top 1000 Port Scan
        xml_tree = ET.parse(in_xml)
        xml_root = xml_tree.getroot()
        
        # Cycle through each host
        for host in xml_root.findall('host'):
            ip_address = host.findall('address')[0].attrib['addr']
            ports_element = host.findall('ports')
            port_child = ports_element[0].findall('port')
            open_ports = []

            # Within each host cycle through the ports
            for port in port_child:
                if port.findall('state')[0].attrib['state'] == 'open':
                    port_id = port.attrib['portid']
                    open_ports.append(port_id)

            # Write results to row
            if len(open_ports) == 0:
                writer.writerow([ip_address, 'no-response', 'no-response'])


if __name__ == '__main__':
    main()
```

### Detected Hosts With Ports + Services

| IP | Port| Service
| :--- | :---| :---|
| 192.168.0.108|443|https
| 192.168.0.109|443|https
| 192.168.0.110|25|tcpwrapped
| 192.168.0.111|443|https
| 192.168.0.112|25|Microsoft Exchange smtpd
| |443|https

```PYTHON
#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os

def main():
    # Path to directory with host XML files
    in_path = '/home/tristram/Scans/Stage_3/'

    # CSV Data
    with open('detected_hosts_with_ports.csv', 'w') as file:
        writer = csv.writer(file)

        # CSV Headers
        writer.writerow(['IP', 'Port', 'Service'])
        for file in sorted(os.listdir(in_path)):
            if file.endswith(".xml"):
                if "no_ports.xml" in file:
                    writer.writerow([file.split('_no_ports.xml')[0], 'no-response', 'no-response'])
                else:
                    # Load Service Scan
                    in_xml = os.path.join(in_path, file)
                    xml_tree = ET.parse(in_xml)
                    xml_root = xml_tree.getroot()

                    # Cycle through each host
                    for host in xml_root.findall('host'):
                        ip_once = True
                        ip_address = host.findall('address')[0].attrib['addr']
                        ports_element = host.findall('ports')
                        port_child = ports_element[0].findall('port')
                        open_ports = []

                        # Within each host cycle through the ports
                        for port in port_child:
                            if port.findall('state')[0].attrib['state'] == 'open':
                                port_id = port.attrib['portid']
                                service_name = port.find('service').get('product')
                                if service_name == None:
                                    service_name = port.find('service').get('name')
                                open_ports.append([port_id, service_name])
                        
                        # Within each port cycle through the open ports
                        if len(open_ports):
                            for op in open_ports:
                                # Ensure we only notate the IP once to keep it clean
                                if ip_once == True:
                                    # Write results to row
                                    writer.writerow([ip_address, op[0], op[1]])
                                    ip_once = False
                                else:
                                    # Write results to row
                                    writer.writerow([None, op[0], op[1]])
                        else:
                            # Write results to row if none
                            writer.writerow([ip_address, 'none', 'none'])

if __name__ == '__main__':
    main()
```

### Detected Hosts With Guessed Operating Systems

| IP | Port
| :--- | :---|
| 192.168.0.113|Unknown
| 192.168.0.114|D-Link DCS-6620G webcam or Linksys BEFSR41 EtherFast router
| 192.168.0.115|Linux 4.9
| 192.168.0.116|Linux 2.6.32
| 192.168.0.117|FreeBSD 9.0-RELEASE - 10.3-RELEASE

```PYTHON
#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv

def main():
    # Path top the os scan file
    in_xml = '/home/tristram/Scans/Stage_4/osdetection.xml'

    # CSV Data
    with open('detected_hosts_os.csv', 'w') as file:
        writer = csv.writer(file)
        # CSV Headers
        writer.writerow(['IP', 'OperatingSystem'])

        # Load OS Scan XML
        xml_tree = ET.parse(in_xml)
        xml_root = xml_tree.getroot()

        # Cycle through each host
        for host in xml_root.findall('host'):
            ip_address = host.findall('address')[0].attrib['addr']
            try:
                os_element = host.findall('os')
                os_name = os_element[0].findall('osmatch')[0].attrib['name']
            except IndexError:
                os_name = 'Unknown'
            
            # Write results to row
            writer.writerow([ip_address, os_name])
            

if __name__ == '__main__':
    main()
```

### Detected Hosts TLS Protocols

#### TLSv1.0

| IP | Port | Protocol
| :--- | :---| :--- |
| 192.168.0.118|443|TLSv1.0
| 192.168.0.119|25|TLSv1.0
| 192.168.0.120|443|TLSv1.0
| 192.168.0.121|443|TLSv1.0
| 192.168.0.122|5061|TLSv1.0

#### TLSv1.1

| IP | Port | Protocol
| :--- | :---| :--- |
| 192.168.0.123|443|TLSv1.1
| 192.168.0.124|25|TLSv1.1
| 192.168.0.125|443|TLSv1.1
| 192.168.0.126|443|TLSv1.1
| 192.168.0.127|5061|TLSv1.1

#### SSLv3.0

| IP | Port | Protocol
| :--- | :---| :--- |
| 192.168.0.128|443|SSLv3.0
| 192.168.0.129|25|SSLv3.0
| 192.168.0.130|443|SSLv3.0
| 192.168.0.131|443|SSLv3.0
| 192.168.0.132|5061|SSLv3.0

```PYTHON
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
```

### Detected SSL Certificates

| IP | Port | CommonName | IssuerCommon | CertStart | CertEnd
| :--- | :--- | :--- | :--- | :--- | :--- |
| 192.168.0.133|443|stay.example.com|DigiCert Global CA G2|2020-05-06|2021-05-06
| 192.168.0.134|443|off.example.com|DigiCert Global CA G2|2019-11-06|2020-11-05
| 192.168.0.135|443|ronins.example.com|DigiCert Global CA G2|2020-05-04|2021-05-05
| 192.168.0.136|443|lawn.example.com|DigiCert Global CA G2|2019-11-15|2020-11-14

```PYTHON
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
```

### Detected Cipher Suites

These reports are built to flag insecure cipher suites like that of virtually any vulnerability scanner. The risk levels were determined by the grade threshold output by Nmap's ssl-enum-ciphers NSE script (https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html). My own preference is to treat F, E and D as high risk and C as a moderate risk, but you can tweak that within the script itself. 

_NOTE: I included extra scripts for other ciphers within the repo but to keep things relatively clean I will include just a few examples below. _

#### Detected High Risk Ciphers

| IP | Port| Cipher Suite
| :--- |:--- |:--- |
|192.168.0.154|443|"TLS_RSA_WITH_NULL_SHA (F)
| ||TLS_RSA_WITH_NULL_MD5 (F)"
|192.168.0.155|443|"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 (D)
| ||TLS_RSA_WITH_NULL_SHA (F)
| ||TLS_RSA_EXPORT1024_WITH_RC4_56_SHA (D)
| ||TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 (E)
| ||TLS_RSA_EXPORT_WITH_DES40_CBC_SHA (E)
| ||TLS_RSA_WITH_NULL_MD5 (F)
| ||TLS_RSA_EXPORT_WITH_RC4_40_MD5 (E)
| ||TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 (D)"

#### Detected Moderate Risk Ciphers

| IP | Port| Cipher Suite
| :--- |:--- |:--- |
| 192.168.0.156|443|"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (C)
| ||TLS_RSA_WITH_RC4_128_MD5 (C)
| ||TLS_RSA_WITH_3DES_EDE_CBC_SHA (C)
| ||TLS_RSA_WITH_RC4_128_SHA (C)"

```PYTHON
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
```

#### Detected 3DES Ciphers

| IP | Port| Cipher Suite
| :--- |:--- |:--- |
| 192.168.0.137|443|"TLS_RSA_WITH_3DES_EDE_CBC_SHA
| ||TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
| 192.168.0.138|443|TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
| 192.168.0.139|443|"TLS_RSA_WITH_3DES_EDE_CBC_SHA
| ||TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"

```PYTHON
#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os


def main():
    # Cipher Risk Lists
    ciphers_list = []
    flagged_ciphers = ''

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
                                                if '3DES' in name:
                                                    flagged_ciphers += name + ','
                                                
                # Stage flagged data for current host
                if flagged_ciphers:    
                    flagged_ciphers = list(set(flagged_ciphers.strip(',').split(',')))
                    ciphers_list.append([ip,port_id,flagged_ciphers])

                # Reset results for next host
                flagged_ciphers = ''

            # Create NULL Cipher Report
            with open('detected_3des_ciphers.csv', 'w') as file:
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
```

#### Detected RC4 Ciphers

| IP | Port| Cipher Suite
| :--- |:--- |:--- |
|192.168.0.148|443|"TLS_RSA_WITH_RC4_128_MD5
| ||TLS_RSA_WITH_RC4_128_SHA"
|192.168.0.149|443|"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
| ||TLS_RSA_WITH_RC4_128_MD5
| ||TLS_RSA_WITH_RC4_128_SHA
| ||TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
| ||TLS_RSA_EXPORT_WITH_RC4_40_MD5"

```PYTHON
#!/usr/bin/python3

import xml.etree.ElementTree as ET
import csv
import os


def main():
    # Cipher Risk Lists
    ciphers_list = []
    flagged_ciphers = ''

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
                                                if 'RC4' in name:
                                                    flagged_ciphers += name + ','
                                                
                # Stage flagged data for current host
                if flagged_ciphers:    
                    flagged_ciphers = list(set(flagged_ciphers.strip(',').split(',')))
                    ciphers_list.append([ip,port_id,flagged_ciphers])

                # Reset results for next host
                flagged_ciphers = ''    

            # Create NULL Cipher Report
            with open('detected_rc4_ciphers.csv', 'w') as file:
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
```

## Wrapping Up

There was a lot of information presented here as well as a lot of Python code. It is my hope that you found it useful and perhaps sparked some inspirational fires for you to think about designing your own enumeration tools or other automated workflows. I invite you to look at your own processes and see if the information you have learned here can be used to help enhance your own processes.

Tristram

