---

# **FAQ: LANradar**

### 1. **What is LANradar?**  
**LANradar** is a powerful tool for network administrators to monitor their LAN (Local Area Network). It scans for connected devices, detects new or unauthorized MAC addresses, and logs activity for enhanced network security.

---

### 2. **What are the main features of LANradar?**  
- **LAN Scanning:** Detect devices connected to your network with periodic scans.  
- **MAC Address Monitoring:** Identify and track new or unauthorized MAC addresses.  
- **Logging & Alerts:** Log detected changes to a file and optionally send syslog alerts to a specified server.  
- **Customization:** Set scan intervals, define a target LAN range, and specify domain names for devices.  
- **Cross-Platform:** Compatible with Linux and other Unix-based systems.  

---

### 3. **How does LANradar work?**  
LANradar uses the `nmap` tool to scan the network range you specify. It compares detected MAC addresses to a whitelist stored in a local file (`lista_mac.txt`) and logs any new or unauthorized devices.

---

### 4. **What are the prerequisites to run LANradar?**  
- Python 3.x  
- `nmap` library (`python-nmap`)  
- Administrator privileges (required for some network operations)  
- Optionally, `ncat` for sending logs via syslog  

---

### 5. **How do I install and run LANradar?**  
1. Clone this repository:  
   ```bash
   git clone https://github.com/yourusername/LANradar.git
   cd LANradar
   ```  
2. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```  
3. Run the script:  
   ```bash
   python3 LANradar.py --lan <LAN_RANGE> --time <SCAN_INTERVAL> [--domain <DOMAIN>] [--log <SYSLOG_IP>]
   ```  

---

### 6. **What happens when an unauthorized device is detected?**  
LANradar will:  
- Log the device's MAC address, IP, and hostname to a local file (`unauthorized.log`).  
- Optionally send an alert to a syslog server if the `--log` option is specified.  

---

### 7. **How can I whitelist a MAC address?**  
Add the MAC address to `lista_mac.txt` in the following format:  
```
<MAC_ADDRESS> <Device_Name>
```  
Example:  
```
00:11:22:33:44:55 Printer
```

### 8. **Who can benefit from LANradar?**  
LANradar is designed for:  
- Network administrators managing small to medium-sized networks.  
- Security professionals looking to detect unauthorized devices.  
- Anyone who wants greater visibility into their home or office network.  

---
