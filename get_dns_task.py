import os
os.environ.setdefault('C_FORCE_ROOT', 'true')


from scapy.all import *
from celery import Celery
from scapy.layers.dns import DNS
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

app = Celery('get_dns_task', backend='amqp', broker='amqp://localhost//')


@app.task
def get_dns_response(host):
    res = sr1(IP(dst="168.126.63.1") / UDP() / DNS(rd=1, qd=DNSQR(qname=host)))
    return res