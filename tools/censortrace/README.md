\# CensorTrace Python Tool

\### Interactive Multi‑Layer Censorship Diagnostic Script



\## Overview



`censortrace.py` is an interactive censorship‑measurement tool that performs:



\- DNS hijacking detection (UDP, TCP, DoH, DoT)

\- HTTP and HTTPS censorship checks

\- TLS/SNI interference detection

\- TCP reset probing

\- Throttling comparison (HTTP vs HTTPS)

\- Optional traceroute, TCP traceroute, ping, and TCP ping

\- Optional packet export for forensic analysis



The tool matches the diagnostic methodology described in the CensorTrace Suite whitepapers.



---



\## How to Run



The tool supports \*\*both\*\*:



\### Interactive mode  

Just run:





python censortrace.py





The script will:



1\. Ask for a target domain  

2\. Ask if you want dig‑style DNS details  

3\. Run all tests  

4\. Show a summary  

5\. Ask if you want to test another domain  



\### Command‑line mode  

You can also pass arguments:





python censortrace.py --traceroute --ping





Available flags include:





--domain --host-header --sni --http-ip --tls-port --dns-timeout --http-timeout --tls-timeout --throttle-timeout --throttle-concurrency --no-color --fake-dns-server --quiet --json --traceroute --traceroute-tcp --ping --tcping --export-packets --version





---



\## Installation



Install dependencies:





pip install -r requirements.txt





---



\## Features



\- Multi‑protocol DNS testing (UDP, TCP, DoH, DoT)

\- Dig‑style DNS decoder with hex dump

\- HTTP/HTTPS censorship detection

\- TLS/SNI manipulation

\- TCP reset detection

\- Throttling measurement

\- Optional traceroute, TCP traceroute, ping, TCP ping

\- JSON output mode

\- Packet export for offline analysis

\- Colorized console output



---



\## File Structure





censortrace-suite/ └── tools/ └── censortrace/ ├── censortrace.py ├── requirements.txt └── README.md





---



\## Notes



\- The tool is safe to run on your own network.

\- No data is sent to external servers except the test requests you initiate.

\- Running as root/admin is not required.



---



\## License



This tool follows the MIT License of the main repository.

