# WARNING — FOR EDUCATIONAL PURPOSES ONLY

A tiny educational packet sniffer that captures HTTP requests on a specified network interface and prints URLs and possible credentials found in payloads.

What it does
- Listens for IP packets and inspects HTTP requests.
- Prints requested URLs and any payloads that look like usernames/passwords.

Requirements
- Python 3
- scapy (install with `pip install scapy`)
- Administrative / root privileges to capture packets on an interface

Usage
1. Open a terminal with administrative/root privileges.
2. Change to the `packet_sniffer` directory.
3. Run:

```bash
python packet_sniffer.py
```

4. When prompted, enter the network interface to sniff on (example: `eth0`, `Wi-Fi`, `Ethernet`).

Notes
- For education only — do not capture network traffic without explicit permission.
- The script decodes payloads as UTF-8; unexpected binary data may raise errors.
