# LocalNetworkScanner
A user-friendly tool to quickly discover and identify devices connected on your local network.

- Quickly finds all devices connected to your local network by scanning the specified IP range.  
- Gathers useful info about each device, including IP address, MAC address, hostname, and manufacturer details.  
- Presents the results in a simple, clean interface powered by Tkinter, so it’s easy to navigate.  
- Keeps the app responsive by running the scan in the background without freezing the window.  
- Provides helpful error messages if something goes wrong or if the IP range entered isn’t valid.  

Install NPCAP before running https://npcap.com/

To install the required dependencies, run:
```bash
pip install scapy requests
```
