#!/usr/bin/python2.7

'''
Copyright (c) 2011 Daniel Arndt and others.
All rights reserved. This program and the accompanying materials are made 
available under the terms of the Eclipse Public License v1.0 which accompanies 
this distribution (please see the LICENSE file), and is available at
http://www.eclipse.org/legal/epl-v10.html
Contributors:

@author: Daniel Arndt
'''

from scapy.all import *
class Flowtbag:
    count = 0
    def __init__(self, filename="test.cap"):
        try:
            sniff(offline=filename, prn=self.callback, store=0)
        except KeyboardInterrupt:
            exit(0)
            
    def callback(self, pkt):
        """The callback function to be used to process each packet
        
        This is the function applied to each individual packet in the capture. 
        
        Args:
            pkt: The packet to be processed
            
        Returns:
        
        Raises:
    
        """
        self.count=self.count+1
        if (IP not in pkt):
            # Ignore non-IP packets
            print "Ignoring non-IP packet %d" % (self.count)
            return
        print "Processing packet %d" % (self.count)
        flags=pkt.sprintf("%TCP.flags%")
        print "%s" % (flags)
        if (pkt.proto == 6):
            print "TCP: [SPort %s | DPort %s]" % (pkt.sport, pkt.dport)
            print "TCP Flags: %s" % (pkt[TCP].flags)
        elif (pkt.proto == 17):
            print "UDP: [SPort %s | DPort %s]" % (pkt.sport, pkt.dport)
    
if __name__ == '__main__':
    Flowtbag()
