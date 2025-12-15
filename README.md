# **Network Toolkit v2.0**

**Network Toolkit v2.0** is a Python-based Command Line Interface (CLI) for network reconnaissance and security monitoring. It combines the power of Python's **Scapy** library for packet manipulation with native Bash scripting for efficient subnet sweeping.

This tool was developed to provide a centralized dashboard for 5 essential network security tasks, ranging from passive OS fingerprinting to active port scanning.

## **🚀 Features**

The toolkit includes five distinct modules accessible via an interactive menu:

* **1\. Packet Sniffer:** An interactive sniffer that captures TCP and UDP traffic. It allows users to target specific host IPs and visualize flags (SYN, ACK, FIN, etc.) in real-time.  
* **2\. Port Scanner:** A targeted scanner that checks the status of common critical ports (21, 22, 23, 25, 80, 110, 443\) on a specific host.  
* **3\. Subnet Scanner:** A fast, parallelized Bash wrapper that performs ping sweeps across a generic subnet (e.g., 192.168.1.x) to identify active hosts.  
* **4\. SYN Scan Detector:** A defensive module that passively listens for SYN floods. It triggers an alert if a single source sends multiple SYN packets within a short time window (Threshold: 5 packets in 3 seconds).  
* **5\. Passive OS Fingerprinting:** Analyzes the Time-To-Live (TTL) of incoming packets to guess the operating system of the source (e.g., Linux/Android vs. Windows vs. Cisco devices).

## **📋 Prerequisites**

To run this tool, you need a Linux environment with Python 3 installed. The tool requires **Root/Sudo** privileges to access raw sockets for Scapy and sniffing functions.

### **Dependencies**

You must install the scapy library:

pip3 install scapy

## **📂 Installation & Directory Structure**

The Python script relies on a specific directory structure to locate the external Bash script. Ensure your repository is organized as follows:

/project-root  
│  
├── cli.py                 \# The main Python application  
└── tools/  
    └── subnet\_scanner.sh  \# The bash script must be inside a 'tools' folder

**Important:** You must grant execution permissions to the Bash script before running the tool:

chmod \+x tools/subnet\_scanner.sh

## **💻 Usage**

Run the main application using sudo (required for network sniffing):

sudo python3 cli.py

### **The Interface**

Upon launching, you will see the main banner and a menu selection:

1. **Select a tool** by typing the corresponding number (1-5).  
2. **Quit** the application by typing q.  
3. Follow the on-screen prompts for IP addresses or Subnets.

## **⚠️ Disclaimer**

This tool is for educational purposes and authorized security testing only.  
The authors are not responsible for any misuse of this toolkit. Ensure you have permission to scan or sniff traffic on the network you are testing.

## **👥 Authors**

* **Anouar Habib Allah**  
* **Ilias Ramadan*  
* **Aya Ennakhlaoui**

### **📝 Notes on Functionality**

* **Subnet Scanner Logic:** The bash script specifically filters for responses containing "64 bytes", which typically indicates a successful ping on Linux/Unix-based systems.  
* **Execution Safety:** The tool handles CTRL+C interrupts gracefully, allowing you to stop sniffing sessions and return to the main menu without crashing.