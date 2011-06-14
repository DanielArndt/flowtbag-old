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
from compiler.ast import While
log = logging.getLogger()
FLOW_TIMEOUT = 600 # Flow timeout in seconds


#===============================================================================
# TCP connection states. These define the finite state machine used for        #
# verifying TCP flow validity.                                                 #
#===============================================================================
class TCP_STATE(object):
    ''' 
    Superclass for a TCP connection state machine.  
    
    Defines the behavior of a state within a generalized finite state machine.
    Currently, the rules perfectly resemble those used by NetMate
    '''
    #TODO: Update the state machine to include more robust checks.
    def update(self, flags, dir, pdir):
        if flags.find("R") >= 0:
            return TCP_CLOSED()
        if flags.find("F") >= 0 and dir == pdir:
            return TCP_FIN()
        # Add all states satisfied by the function in the map /tr/ given /flags/
        next_state = [ s for f, s in self.tr if f(flags, dir, pdir)]
        try:
            return eval(next_state[0])()
        except:
            return self # Default to no transition

    def __str__(self):
        return self.__class__.__name__

class TCP_START(TCP_STATE):
    tr = [(lambda f, dir, pdir: f.find("S") >= 0 and dir == pdir, "TCP_SYN")]

class TCP_SYN(TCP_STATE):
    tr = [(lambda f, dir, pdir: f.find("S") >= 0 and
           f.find("A") >= 0 and dir != pdir, "TCP_SYNACK")]

class TCP_SYNACK(TCP_STATE):
    tr = [(lambda f, dir, pdir: f.find("A") >= 0  and dir == pdir, "TCP_ESTABLISHED")]

class TCP_ESTABLISHED(TCP_STATE):
    tr = []

class TCP_FIN(TCP_STATE):
    tr = [(lambda f, dir, pdir: f.find("A") >= 0 and dir != pdir, "TCP_CLOSED")]

class TCP_CLOSED(TCP_STATE):
    tr = []

#------------------------------------------------------------------------------ 

class Flow:
    '''
    Represents one flow to be stored in a flowtbag.
    
    An object of this class represents one flow in a flowtbag. The Flow object 
    contains several statistics about the flow as well as stores the first 
    packet of the flow for reference. 
    
    '''
    def __init__(self, pkt, id):
        '''
        Constructor. Initialize all values.
        '''
        # Set initial values
        self.id = id
        self.first_packet = pkt
        self.valid = False
        self.pdir = "f"
        self.first = pkt.time
        self.flast = 0
        self.blast = 0
        if pkt.proto == 6:
            self.cstate = TCP_START() # Client state
            self.sstate = TCP_START() # Server state
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
        self.total_fhlen = 0
        self.total_bhlen = 0

    def __repr__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self.id, self.srcip, self.srcport, self.dstip, self.dstport, self.proto)

    def __str__(self):
        return ','.join(map(str, [
                        self.id,
                        self.total_fpackets, self.total_fvolume,
                        self.total_bpackets, self.total_bvolume]))

    def update_tcp_state(self, pkt):
        '''
        Updates the TCP connection state
        
        Checks to see if a valid TCP connection has been made. The function uses
        a finite state machine implemented through the TCP_STATE class and its 
        sub-classes.

        '''
        flags = pkt.sprintf("%TCP.flags%")
        log.debug("FLAGS: %s" % (flags))
        # Update client state
        self.cstate = self.cstate.update(flags, "f", self.pdir)
        log.debug("Updating TCP connection cstate to %s" % (self.cstate))
        # Update server state
        self.sstate = self.sstate.update(flags, "b", self.pdir)
        log.debug("Updating TCP connection sstate to %s" % (self.sstate))

    def update_status(self, pkt):
        '''
        Updates the status of a flow (valid/invalid)
        
        Updates the status of a flow, checking if the flow is a valid flow.
        
        In the case of UDP, this is a simple check upon whether at least one
        packet has been sent in each direction.
        
        In the case of TCP, the validity check is a little more complex. A valid
        TCP flow requires that a TCP connection is established in the usual way.
        Furthermore, the TCP flow is terminated when a TCP connection is closed,
        or upon a timeout defined by FLOW_TIMEOUT.
        
        '''
        if pkt.proto == 19:
            # UDP
            # Skip if already labelled valid
            if self.valid: return
            # Check if a packet has been received from backward direction. One
            # packet has already been sent in forward direction to initiate.
            if pkt.len > 8:
                # TODO: Check for 1 packet in each direction
                self.valid = True
        elif pkt.proto == 6:
            # TCP
            if not self.valid:
                #Check validity
                pass
            self.update_tcp_state(pkt)

    def get_last(self):
        '''
        Reimplementation of the NetMate flowstats method 
        getLast(struct flowData_t). 
        
        Returns:
            The timestamp of the last packet.
        '''
        if (self.blast == 0):
            return self.flast
        elif (self.flast == 0):
            return self.blast
        else:
            return self.flast if (self.flast > self.blast) else self.blast

    def get_proto_hlen(self, pkt):
        '''
        Returns:
            The protocol header length 
        '''
        if (pkt.proto == 19):
            return 8
        elif (pkt.proto == 6):
            return pkt[TCP].dataofs * 32 / 8 # TCPHL * 32 bit word / 8 bits per byte

    def add(self, pkt):
        '''
        Add a packet to the current flow.
        
        This function adds the packet, provided as an argument, to the flow.
        
        Args:
            pkt: The packet to be added
        '''
        len = pkt.len
        iphlen = pkt.ihl * 32 / 8 # ihl field * 32-bits / 8 bits in a byte
        protohlen = self.get_proto_hlen(pkt)
        log.debug("protoHLEN: %d" % (protohlen))
        now = pkt.time
        assert (now >= self.first)

        # Ignore re-ordered packets
        if (now < self.get_last()):
            log.debug("Flow: ignoring reordered packet. %d < %d" %
                      (now, self.get_last))
            raise NotImplementedError

        #Check validity
        self.update_status(pkt)

        if (pkt[IP].src == self.first_packet[IP].src):
            self.pdir = "f"
        else:
            self.pdir = "b"

        if self.pdir == "f":
            # Packet is travelling in the forward direction
            # Calculate some statistics
            self.total_fpackets += 1
            self.total_fvolume += len
            self.total_fhlen += iphlen + protohlen
            # Update the last forward packet timestamp
            self.flast = now
        else:
            # Packet is travelling in the backward direction
            # Calculate some statistics
            self.total_bpackets += 1
            self.total_bvolume += len
            self.total_bhlen += iphlen + protohlen
            # Update the last backward packet timestamp
            self.blast = now
