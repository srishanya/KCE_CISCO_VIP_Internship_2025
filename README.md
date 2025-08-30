# 🌐 Network Automation & Load Analysis Tool

## 🚀 Overview
Automates network topology setup, configuration, load analysis, and fault simulation.  
Perfect for testing, validating, and optimizing network performance.

---

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
