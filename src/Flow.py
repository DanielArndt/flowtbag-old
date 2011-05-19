#!/usr/bin/python

'''
Copyright (c) 2011 Daniel Arndt and others.
All rights reserved. This program and the accompanying materials are made 
available under the terms of the Eclipse Public License v1.0 which accompanies 
this distribution (please see the LICENSE file), and is available at
http://www.eclipse.org/legal/epl-v10.html
Contributors:

@author: Daniel Arndt <danielarndt@gmail.com>
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
        # Basic flow identification criteria
        self.srcip = pkt[IP].src
        self.srcport = pkt.sport
        self.dstip = pkt[IP].dst
        self.dstport = pkt.dport
        self.proto = pkt.proto
        #

        self.total_fpackets = 1
        #self.total_fvolume
        self.total_bpackets = 0
        #self.total_bvolume
        #self.min_fpktl
        #self.mean_fpktl
        #self.max_fpktl
        #self.std_fpktl
        #self.min_bpktl
        #self.mean_bpktl
        #self.max_bpktl
        #self.std_bpktl
        #self.min_fiat
        #self.mean_fiat
        #self.max_fiat
        #self.std_fiat
        #self.min_biat
        #self.mean_biat
        #self.max_biat
        #self.std_biat
        #self.duration
        #self.min_active
        #self.mean_active
        #self.max_active
        #self.std_active
        #self.min_idle
        #self.mean_idle
        #self.max_idle
        #self.std_idle
        #self.sflow_fpackets
        #self.sflow_fbytes
        #self.sflow_bpackets
        #self.sflow_bbytes
        #self.fpsh_cnt
        #self.bpsh_cnt
        #self.furg_cnt
        #self.burg_cnt
        #self.total_fhlen
        #self.total_bhlen

    def __repr__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self.id, self.srcip, self.srcport, self.dstip, self.dstport, self.proto)

    def __str__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self.id, self.srcip, self.srcport, self.dstip, self.dstport, self.proto)

    def add_to_flow(self, pkt):
        """Adds a packet to the current flow. 
        
        This method adds the provided packet to the flow.  
        
        Args:
            pkt: The packet to be added
        """
        if (pkt[IP].src == self.first_packet[IP].src):
            # Packet is traveling in the forward direction
            self.total_fpackets += 1
        else:
            # Packet is traveling in the backward direction
            self.total_bpackets += 1

    #def export(self):
    #    return "(%d, %s, %d, %s, %d)" % (self.id, self.first_packet)
