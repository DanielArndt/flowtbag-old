#!/usr/bin/python

'''
   Copyright 2011 Daniel Arndt

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Contributors:

   @author: Daniel Arndt <danielarndt@gmail.com>
'''

from scapy.all import *
log = logging.getLogger()

class TCP_STATE(object):
    def update(self, input):
        try:
            return eval(self.tr[input])()
        except:
            return self

class TCP_START(TCP_STATE):
    tr = {"S":"TCP_SYN"}
    def __str__(self):
        return "TCP_START"

class TCP_SYN(TCP_STATE):
    tr = {"SA":"TCP_SYNACK"}
    def __str__(self):
        return "TCP_SYN"

class TCP_SYNACK(TCP_STATE):
    tr = {"A":"TCP_ESTABLISHED"}
    def __str__(self):
        return "TCP_SYNACK"

class TCP_ESTABLISHED(TCP_STATE):
    pass
    def __str__(self):
        return "TCP_ESTABLISHED"

class Flow:
    """
    classdocs
    """
    def __init__(self, pkt, id):
        """
        Constructor
        """
        # Set initial values
        self.id = id
        self.first_packet = pkt
        self.valid = False
        if pkt.proto == 6:
            self.state = TCP_START()
        # Set the initial status of the flow
        self.update_status(pkt)
        # Basic flow identification criteria
        self.srcip = pkt[IP].src
        self.srcport = pkt.sport
        self.dstip = pkt[IP].dst
        self.dstport = pkt.dport
        self.proto = pkt.proto
        #
        self.total_fpackets = 1
        self.total_fvolume = pkt.len
        self.total_bpackets = 0
        self.total_bvolume = 0
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
        return ','.join(map(str, [
                        self.id,
                        self.total_fpackets, self.total_fvolume,
                        self.total_bpackets, self.total_bvolume]))

    def update_tcp_state(self, pkt):
        # Update the TCP connection state
        flags = pkt.sprintf("%TCP.flags%")
        log.debug("FLAGS: %s" % (flags))
        self.state = self.state.update(flags)
        log.debug("Updating TCP connection state  to %s" % (self.state))

    def update_status(self, pkt):
        """Updates the status of a flow.
        
        """
        # Skip if the 
        if pkt.proto == 19:
            # UDP
            # Skip if already labelled valid
            if self.valid: return
            # Check if a packet has been received from backward direction. One
            # packet has already been sent in forward direction to initiate.
            if self.total_bpackets > 0:
                self.valid = True
        elif pkt.proto == 6:
            # TCP
            if not self.valid:
                #Check validity
                pass
            self.update_tcp_state(pkt)

    def add_to_flow(self, pkt):
        """Adds a packet to the current flow. 
        
        This function adds the provided packet to the flow.  
        
        Args:
            pkt: The packet to be added
        """
        length = pkt.len
        if (pkt[IP].src == self.first_packet[IP].src):
            # Packet is traveling in the forward direction
            self.total_fpackets += 1
            self.total_fvolume += length
        else:
            # Packet is traveling in the backward direction
            self.total_bpackets += 1
            self.total_bvolume += length
        self.update_status(pkt)
