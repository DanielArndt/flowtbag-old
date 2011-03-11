'''
Created on Mar 10, 2011

@author: Daniel Arndt
'''

from scapy.all import *

def callback(pkt):
    flags=pkt.sprintf("%TCP.flags%")
    if (pkt.proto == 6):
        print "TCP: [SPort %s | DPort %s]" % (pkt.sport, pkt.dport)
    elif (pkt.proto == 17):
        print "UDP: [SPort %s | DPort %s]" % (pkt.sport, pkt.dport)

if __name__ == '__main__':
    try:
        sniff(offline="test.cap", prn=callback, store=0, count = 5)
    except KeyboardInterrupt:
        exit(0)