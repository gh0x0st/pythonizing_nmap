# Question of Trust

The xml.etree.ElementTree module provides an easy-to-use library to parse XML data that you trust, such as the XML ouput generated from NMAP. However, when dealing with data you do not trust, there are better avenues. 

The below information comes from https://docs.python.org/3/library/xml.html#xml-vulnerabilities as of 11/19/2021.

## Vulnerabilities For ElementTre

| Attack    | Vulnerable |
| :---------|------------|
| billion laughs | **Yes** |
| quadratic blowup | **Yes** |  
| external entity expansion | No |
| DTD retrieval | No |
| decompression bomb | No |

## Attack Descriptions

The Billion Laughs attack – also known as exponential entity expansion – uses multiple levels of nested entities. Each entity refers to another entity several times, and the final entity definition contains a small string. The exponential expansion results in several gigabytes of text and consumes lots of memory and CPU time.

The quadratic blowup attack is similar to a Billion Laughs attack; it abuses entity expansion, too. Instead of nested entities it repeats one large entity with a couple of thousand chars over and over again. The attack isn’t as efficient as the exponential case but it avoids triggering parser countermeasures that forbid deeply-nested entities.

## Alternative Package

The defusedxml library is a pure Python package with modified subclasses of all stdlib XML parsers that prevent any potentially malicious operation. Use of this package is recommended for any server code that parses untrusted XML data. The package also ships with example exploits and extended documentation on more XML exploits such as XPath injection.

## References
* https://docs.python.org/3/library/xml.html#xml-vulnerabilities
* https://pypi.org/project/defusedxml/
