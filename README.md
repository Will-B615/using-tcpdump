# Lab: Capturing and Filtering Network Traffic with `tcpdump` on Linux

## Activity Overview

As a security analyst, it’s important to know how to **capture and filter network traffic in a Linux environment**. You’ll also need to understand the basic concepts associated with **network interfaces**, such as which interfaces exist on a host and which ones are suitable for packet capture.

This activity walks through the end‑to‑end use of `tcpdump` to:

- Discover interfaces  
- Inspect live traffic  
- Capture traffic to a file  
- Filter and analyze stored packet data  

---

## Scenario

You’re a **network analyst** who needs to use `tcpdump` to capture and analyze **live network traffic** from a Linux virtual machine.

You will:

1. Identify network interfaces  
2. Inspect live network traffic using `tcpdump`  
3. Capture traffic to `capture.pcap`  
4. Filter and inspect captured data from the pcap file  

---

## Task 1. Identify Network Interfaces

**Task 1.** Identify network interfaces that can be used to capture network packet data

<img width="873" height="513" alt="Identify Network Interfaces" src="https://github.com/user-attachments/assets/0cca25a7-234e-49ef-84f2-e271fb7f1ecc" />

**Description:**
Displays the current network interface configuration, including IP addresses, netmasks, MAC addresses, and status for each interface (such as eth0 and lo).

**Function:**
This command helps identify which network interfaces exist on the Linux VM and see their basic settings so you can choose the correct interface for packet capture.

**Benefit:**
Ensures you target the right interface (for example, eth0 instead of the loopback lo) when capturing traffic, reducing mistakes and helping you focus on real network traffic instead of irrelevant local-only traffic.

**Task 1.1** Identify interface options available for packet capture

<img width="873" height="320" alt="Interface options" src="https://github.com/user-attachments/assets/907db1ec-a363-4d3f-874d-a4a06c4d4519" />

**Description:**
Lists all network interfaces that tcpdump can capture from, along with an index number for each.

​
**Function:**
Provides a tcpdump‑aware view of available capture interfaces, which can be useful on systems where ifconfig is unavailable or when you want to reference interfaces by index.

**Benefit:**
Ensures tcpdump is pointed at a valid interface, preventing errors and making it easier to script or automate captures across different systems and environments.

---

## Task 2. Inspect network traffic of a network interface with tcpdump

**Task 2.** Use tcpdump to filter live network packet traffic on an interface

<img width="878" height="707" alt="Live network packet data pt1" src="https://github.com/user-attachments/assets/6725f785-f969-4555-b4cc-069a0b6349f5" />

**Description:**
Captures 5 packets of live traffic on interface eth0 and prints a verbose, human‑readable description of each packet to the terminal.

**Function:**
-i eth0: Listens specifically on the eth0 network interface.

-v: Shows additional header details (TTL, flags, lengths, etc.).

-c5: Stops automatically after 5 packets have been captured.

**Benefit:**
Provides a quick “snapshot” of live traffic on a specific interface, allowing you to confirm that packets are flowing, inspect key header fields, and spot unusual behavior without generating large amounts of data.

---

## Task 3. Capture network traffic with tcpdump

**Task 3.** Use tcpdump to save captured netword data to a packet capture file

<img width="887" height="102" alt="Capture web traffic" src="https://github.com/user-attachments/assets/321883a3-adf7-412d-8958-12059852feae" />

**Description:**
Captures 9 packets of HTTP (TCP port 80) traffic on eth0, does not resolve hostnames or service names, saves the packets to capture.pcap, and runs in the background.

**Function:**
-i eth0: Capture only on the eth0 interface.

-nn: Disable DNS and service‑name lookups, keeping IPs and ports numeric.

-c9: Stop after 9 packets.

port 80: Filter to only packets whose source or destination port is 80.

-w capture.pcap: Write raw packet data to a pcap file.

&: Run the capture in the background so the shell prompt remains usable.

**Benefit:**
Produces a focused pcap file containing just HTTP traffic, which is small, shareable, and easy to analyze later in tools like Wireshark—ideal for troubleshooting, training, or documenting evidence during investigations.

**Task 3.1** Use curl to generate some HTTP (port 80) traffic:

<img width="880" height="257" alt="curl generated HTTP traffic" src="https://github.com/user-attachments/assets/30e83431-bd16-4375-8920-b7ef41554813" />

**Description:**
Uses curl (a command‑line HTTP client) to send a web request to opensource.google.com and print the response to the terminal.

**Function:**
Generates real HTTP (TCP port 80 or 443, depending on URL/protocol) traffic from the VM to a remote web server, which can then be observed or captured by tcpdump.

**Benefit:**
Gives you a predictable stream of web traffic on demand, making it easy to create test traffic for captures and confirm that filters, interfaces, and capture commands are working correctly.

**Task 3.2** Verify captured packet data

<img width="723" height="51" alt="verify packet data capture" src="https://github.com/user-attachments/assets/e2566152-b9b3-46cf-9fd9-afb35112bc4d" />

**Description:**
Lists capture.pcap in long format, showing its size, permissions, timestamps, and ownership.

**Function:**
Verifies that the pcap file was created and contains data (non‑zero size) after a tcpdump capture run.

**Benefit:**
Provides quick confirmation that the capture completed successfully and that you have a file ready for further analysis, preventing time wasted trying to read or analyze a file that was never created.

---

## Task 4. Filter the captured packet data

**Task 4.** Use tcpdump to filter data from the previously saved packet capture file

<img width="875" height="628" alt="Filter packet header pt1" src="https://github.com/user-attachments/assets/5397f559-4de8-44ff-9599-9a23ce57d771" />

<img width="871" height="678" alt="Filter packet header pt2" src="https://github.com/user-attachments/assets/799671cd-1977-46a7-b07f-9d11b5285601" />

<img width="882" height="75" alt="Filter packet header pt3" src="https://github.com/user-attachments/assets/6d45f039-deef-4c16-a516-daa9999e6357" />

**Description:**
Reads packets from the existing capture.pcap file instead of from the network and prints verbose, numeric header information for each packet.

**Function:**
-nn: Keep IP addresses and ports numeric (no lookups).

-r capture.pcap: Read packets from the pcap file.

-v: Show extra header details for each packet.

**Benefit:**
Allows you to review captured traffic offline without affecting the live system, making it easier to analyze flows, flags, and header fields carefully at your own pace—useful for incident review, reporting, and knowledge sharing.

**Task 4.1** Use the tcpdump command to filter the extended packet data from the capture.pcap capture file:

<img width="873" height="696" alt="Filter extended packet data pt1" src="https://github.com/user-attachments/assets/e6e840ad-5ec6-4521-ba77-a36749b5089b" />

<img width="875" height="667" alt="Filter extended packet data pt2" src="https://github.com/user-attachments/assets/bd36882f-0403-476a-9d28-d8f2d3ee85d1" />

<img width="867" height="643" alt="Filter extended packet data pt3" src="https://github.com/user-attachments/assets/6237fcb4-ecff-4c3a-931f-2330a4c56eb2" />

<img width="872" height="352" alt="Filter extended packet data pt4" src="https://github.com/user-attachments/assets/b54cec63-eab1-49c3-bb73-7c3c51cc307d" />

**Description:**
Reads packets from capture.pcap and prints both hex and ASCII representations of packet contents, with numeric addresses and ports.

**Function:**
-nn: Disable name lookups.

-r capture.pcap: Read from an existing pcap file.

-X: Show packet data in hex plus ASCII side‑by‑side.

**Benefit:**
Exposes the actual payload of packets, enabling you to spot strings, protocol details, or suspicious patterns (for example, credentials, commands, or malware signatures), which is critical for deep forensics and malware analysis.

---

## Summary Overview

In this lab, I used a small set of powerful Unix commands to walk through the full lifecycle of network analysis with tcpdump on a Linux virtual machine. I started with sudo ifconfig and sudo tcpdump -D to discover which network interfaces were available and which ones were suitable for packet capture. Then I inspected live traffic with sudo tcpdump -i eth0 -v -c5, which helped me see how packets appear on the wire in real time.
Next, I focused on capturing specific HTTP traffic by generating web requests with curl opensource.google.com and recording only port 80 packets into a reusable pcap file using sudo tcpdump -i eth0 -nn -c9 port 80 -w capture.pcap &, and I confirmed its creation with ls -l capture.pcap. This showed me how to create targeted, shareable captures that I can analyze later.
Finally, I moved to offline analysis with sudo tcpdump -nn -r capture.pcap -v and sudo tcpdump -nn -r capture.pcap -X, examining both protocol headers and raw payload data. Together, these commands demonstrated how I can use tcpdump to support my workflow as a security analyst—from identifying interfaces and generating traffic to capturing, storing, and deeply inspecting packets for troubleshooting, threat hunting, and forensic investigations in real‑world Linux environments.

---












