# 🌐 Network Automation & Load Analysis Tool

## 🚀 Overview
This report outlines the development of an auto-topology generation and network simulation system
as per the Networking Problem Statement of the Cisco Virtual Internship Program 2025. The tool
automatically parses router configuration files, constructs a network topology, validates settings,
and simulates performance and failures. Automates network topology setup, configuration, load analysis, and fault simulation.  
Perfect for testing, validating, and optimizing network performance.

2. Input Configuration Files
Users provide a directory containing router configuration dumps such as:
- Conf/R1/config.dump
- Conf/R2/config.dump
- Conf/R3/config.dump
Each file includes interface settings, IP addresses, bandwidth, routing protocols (OSPF/BGP),
VLANs, and more.

3. Auto Topology Generation
- The system parses config files to extract link relationships, interface details, and bandwidth.
- A hierarchical topology is generated connecting routers, switches, and end devices.
- Visual layout auto-generates using extracted metadata.

  4. Configuration Validation and Optimization
The tool checks for:
- Missing configuration files (e.g., a switch config for an endpoint)
- Duplicate IPs in the same subnet
- Incorrect VLAN tags or gateway assignments
- MTU mismatches
- Potential network loops
- Suggestions to replace OSPF with BGP when scalability is needed
  
5. Load Management and Traffic Awareness
- Parses bandwidth details from configs to estimate capacity.
- Models expected traffic per application type (e.g., video conferencing vs file transfer).
- If a link is overloaded, recommends load balancing or path offloading.
- Provides fallback routing paths for low-priority traffic.
  
6. Simulation and Fault Injection
- Day-1 simulation includes ARP, OSPF discovery, and neighbor formation.
- Day-2 testing includes link failure simulation and behavior analysis:
- Impact on endpoints
- Routing table reconvergence
- MTU issue effect on data delivery
- Simulation can be paused, edited, and resumed.

  7. System Architecture
- Each router/switch is represented as a multithreaded object.
- IPC (FIFO/TCP sockets) used to exchange metadata packets.
- Logs maintained per thread to simulate MAC/IP layer activity.
- Optional generation of real IP packets for testing.

- 
## 📁 Project Structure
Cisco Virtual Internship/
├── Networking_Pathway(1).pkt # Packet Tracer file
├── project/
│ ├── output/ # Simulation & analysis results
│ ├── configs/ # Device configurations
│ ├── *.csv # Network link/device data
│ └── network_tool.py # Main automation script


## ✨ Features
- 🖥️ **Auto Topology Management** – Generates & configures devices automatically  
- 📊 **Load Analysis** – Monitors traffic & identifies congestion  
- ⚡ **Fault Simulation** – Tests rerouting with link failures/bandwidth drops  
- ✅ **Validation & Reporting** – Generates logs & validation reports  

---

## 🛠️ Usage
1. **Analyze Network Load**
bash:
python project/network_tool.py --analyze_load --configs project/configs --links project/*.csv
Simulate Network Faults

bash:
python project/network_tool.py --simulate --sim-seconds 8
Validate Configuration

bash:
python project/network_tool.py --validate --configs project/configs
Generate Topology

bash:
python project/network_tool.py --generate_topology --input project/*.csv

📂 **##Input Files**
project/configs/ → Device configurations
*.csv → Network link/device data
Networking_Pathway(1).pkt → Packet Tracer visualization

📊 **##Output**
project/output/ → Logs, load reports, validation results

💻 **##CLI Proof Commands**
Verify configurations with:

bash:
show ip route
show ip interface brief
ping <destination-ip>

🛠️ **##Technologies**
Python
CSV/JSON for configuration & data
Packet Tracer for network visualization

 Conclusion
The auto-topology tool simplifies the creation, validation, and simulation of networks by reading raw
configs and generating meaningful visual and diagnostic outputs. It can be a foundational
component for smarter, simulation-driven network design.

