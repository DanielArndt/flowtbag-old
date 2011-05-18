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

class Flow:
    '''
    classdocs
    '''
    def __init__(self, pkt, id):
        '''
        Constructor
        '''
        self.id = id
        self.first_packet = pkt
        # Basic identification criteria
        self.srcip = pkt[IP].src
        self.srcport = pkt.sport
        self.dstip = pkt[IP].dst
        self.dstport = pkt.dport
        self.proto = pkt.proto
        #
        
        self.total_fpackets = 1
        self.total_bpackets = 0
    
    def __repr__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self.id, self.srcip, self.srcport,self.dstip,self.dstport,self.proto) 
        
    def __str__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self.id, self.srcip, self.srcport,self.dstip,self.dstport,self.proto) 
        
    def add(self, pkt):
        self.total_fpackets += 1
        self.total_bpackets += 1
        
    #def export(self):
    #    return "(%d, %s, %d, %s, %d)" % (self.id, self.first_packet)

class Flowtbag:
    '''
    classdocs
    '''
    def __init__(self, filename="test.cap"):
        try:
            self.count = 0
            self.flow_count = 0
            self.active_flows = {}
            sniff(offline=filename, prn=self.callback, store=0)
        except KeyboardInterrupt:
            exit(0)
            
    def __repr__(self):
        return "A flowtbag"
        
    def __str__(self):
        return "flowtbag"
            
    def callback(self, pkt):
        """The callback function to be used to process each packet
        
        This is the function applied to each individual packet in the capture. 
        
        Args:
            pkt: The packet to be processed
            
        Returns:
        
        Raises:
    
        """
        self.count += 1
        if (IP not in pkt):
            # Ignore non-IP packets
            print "Ignoring non-IP packet %d" % (self.count)
            return
        print "Processing packet %d" % (self.count)
        srcip = pkt[IP].src
        srcport = pkt.sport
        dstip = pkt[IP].dst
        dstport = pkt.dport
        proto = pkt.proto
        flow_tuple = (srcip, srcport, dstip, dstport, proto)
        flow_tuple = self.sortIPs(flow_tuple)

        if (pkt.proto == 6):
            # TCP
            if (flow_tuple not in self.active_flows):
                self.flow_count += 1
                self.active_flows[flow_tuple] = Flow(pkt, self.flow_count)
                print "Created flow %d" % (self.flow_count)
            else:
                print "Adding packet %d to flow %s" % \
                    (self.count, self.active_flows[flow_tuple])
                self.active_flows[flow_tuple].add(pkt)
            #print "%s" % (flow_tuple,)
            #print "TCP Flags: %s" % (pkt[TCP].flags)
            #flags=pkt.sprintf("%TCP.flags%")
            #print "%s" % (flags)
        elif (pkt.proto == 17):
            # UDP
            print "UDP: [SPort %s | DPort %s]" % \
                (pkt.sport, pkt.dport)
    
    def sortIPs(self, t):
        if (t[2] < t[0]):
            new_tuple = (t[2],t[3],t[0],t[1], t[4])
        else:
            new_tuple = t
        return new_tuple
    
if __name__ == '__main__':
    Flowtbag()
