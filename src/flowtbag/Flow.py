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
# Retrieve the default logger, should have been initialized by the Flowtbag.
log = logging.getLogger()

#---------------------------------------------------------------------- Settings
FLOW_TIMEOUT = 600 # Flow timeout in seconds 
IDLE_THRESHOLD = 1.0
#----------------------------------------------------------------- End: Settings

def stddev(sqsum, sum, count):
    #log.debug("sqsum, sum, count: %d, %d, %d" % (sqsum, sum, count))
    return long(math.sqrt((sqsum - (sum ** 2 / count)) / (count - 1)))

def tcp_set(flags, find):
    '''
    Checks if a flag is set or not.
    
    Args:
        flags - The string encoded set of flags
        find - The flag to find
    Returns:
        True - if the /find/ flag is set
        False - otherwise
    '''
    return True if flags.find(find) >= 0 else False

#==============================================================================#
# TCP connection states. These define the finite state machine used for        #
# verifying TCP flow validity.                                                 #
#==============================================================================#
class TCP_STATE(object):
    ''' 
    Superclass for a TCP connection state machine.  
    
    Defines the behavior of a state within a generalized finite state machine.
    Currently, the rules perfectly resemble those used by NetMate
    '''
    #TODO: Update the state machine to include more robust checks. Current 
    # implementation imitates NetMate state machine. 
    def update(self, flags, dir, _pdir):
        '''
        Updates the TCP state machine.
        
        First the RST and FIN flags are checked. If either of these are set, the
        connection state is set to either TCP_CLOSED or TCP_FIN respectively.
        Next, the function attempts to find a transition in the map called /tr/.
        If no transition is found, then the function returns itself. 
        
        '''
        if tcp_set(flags, "R"):
            return TCP_CLOSED()
        if tcp_set(flags, "F") and dir == _pdir:
            return TCP_FIN()
        # Add all states satisfied by the function in the map /tr/ given /flags/
        next_state = [ s for f, s in self.tr if f(flags, dir, _pdir)]
        try:
            return eval(next_state[0])()
        except:
            return self # Default to no transition

    def __str__(self):
        return self.__class__.__name__

class TCP_START(TCP_STATE):
    tr = [(lambda flags, dir, pdir: tcp_set(flags, "S") and dir == pdir, "TCP_SYN")]

class TCP_SYN(TCP_STATE):
    tr = [(lambda flags, dir, pdir: tcp_set(flags, "S") and
           tcp_set(flags, "A") and dir != pdir, "TCP_SYNACK")]

class TCP_SYNACK(TCP_STATE):
    tr = [(lambda flags, dir, pdir: tcp_set(flags, "A") and
           dir == pdir, "TCP_ESTABLISHED")]

class TCP_ESTABLISHED(TCP_STATE):
    tr = []

class TCP_FIN(TCP_STATE):
    tr = [(lambda flags, dir, pdir: tcp_set(flags, "A") and
           dir != pdir, "TCP_CLOSED")]

class TCP_CLOSED(TCP_STATE):
    tr = []
#-------------------------------------------------------- End: TCP state machine

#==============================================================================#
# Begin code for Flow class                                                    #
#==============================================================================#
class Flow:
    '''
    Represents one flow to be stored in a flowtbag.
    
    An object of this class represents one flow in a flowtbag. The Flow object 
    contains several statistics about the flow as well as stores the first 
    packet of the flow for reference.
    
    Variable naming conventions:
        Prefix - desc
        _  - Instance variable used for storing information about the flow which 
             is important for calculations or identification purposes but is not
             part of the output.
            
        a_ - Instance variables representing an attribute to be exported as a
             flow attribute (feature).
             
        c_ - Counter variables, used for counting totals and other statistics to
             help in calculating attributes. 
    
    '''
    def __init__(self, pkt, id):
        '''
        Constructor. Initialize all values.
        '''
        # Set initial values
        self._id = id
        self._first_packet = pkt
        self._valid = False
        self._pdir = "f"
        self._first = pkt.time
        self._flast = pkt.time
        self._blast = 0
        # Basic flow identification criteria
        self.a_srcip = pkt[IP].src
        self.a_srcport = pkt.sport
        self.a_dstip = pkt[IP].dst
        self.a_dstport = pkt.dport
        self.a_proto = pkt.proto
        #
        self.a_total_fpackets = 1
        self.a_total_fvolume = pkt.len
        self.a_total_bpackets = 0
        self.a_total_bvolume = 0
        self.a_min_fpktl = 0
        self.a_mean_fpktl = 0
        self.a_max_fpktl = 0
        self.a_std_fpktl = 0
        self.c_fpktl_sqsum = (pkt.len ** 2)
        self.a_min_bpktl = 0
        self.a_mean_bpktl = 0
        self.a_max_bpktl = 0
        self.a_std_bpktl = 0
        self.c_bpktl_sqsum = 0
        self.a_min_fiat = 0
        self.a_mean_fiat = 0
        self.a_max_fiat = 0
        self.a_std_fiat = 0
        self.c_fiat_sum = 0
        self.c_fiat_sqsum = 0
        self.c_fiat_count = 0
        self.a_min_biat = 0
        self.a_mean_biat = 0
        self.a_max_biat = 0
        self.a_std_biat = 0
        self.c_biat_sum = 0
        self.c_biat_sqsum = 0
        self.c_biat_count = 0
        self.a_duration = 0 #TODO: Count this
        self.a_min_active = -1
        self.a_mean_active = -1
        self.a_max_active = -1
        self.a_std_active = -1
        self.c_active_start = self._first
        self.c_active_time = 0
        self.c_active_sqsum = 0
        self.c_active_count = 0
        self.a_min_idle = -1
        self.a_mean_idle = -1
        self.a_max_idle = -1
        self.a_std_idle = -1
        self.c_idle_time = 0
        self.c_idle_sqsum = 0
        self.c_idle_count = 0
        self.a_sflow_fpackets = 0
        self.a_sflow_fbytes = 0
        self.a_sflow_bpackets = 0
        self.a_sflow_bbytes = 0
        if pkt.proto == 6:
            # TCP specific
            # Create state machines for the client and server 
            self._cstate = TCP_START() # Client state
            self._sstate = TCP_START() # Server state
            # Set TCP flag stats
            flags = pkt.sprintf("%TCP.flags%")
            if (tcp_set(flags, "P")):
                self.a_fpsh_cnt = 1
            else:
                self.a_fpsh_cnt = 0
            self.a_bpsh_cnt = 0
            if (tcp_set(flags, "U")):
                self.a_furg_cnt = 1
            else:
                self.a_furg_cnt = 0
            self.a_burg_cnt = 0
        self.a_total_fhlen = 0
        self.a_total_bhlen = 0
        self.update_status(pkt)

    def __repr__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self._id, self.a_srcip, self.a_srcport, self.a_dstip,
             self.a_dstport, self.a_proto)

    def __str__(self):
        '''
        Exports the stats collected.
        '''
        self.a_mean_fpktl = self.a_total_fvolume / self.a_total_fpackets
        self.a_std_fpktl = stddev(self.c_fpktl_sqsum,
                                  self.a_total_fvolume,
                                  self.a_total_fpackets) \
            if self.a_total_fpackets > 1 else (0)
        self.a_mean_bpktl = self.a_total_bvolume / self.a_total_bpackets \
            if self.a_total_bpackets > 0 else (-1)
        self.a_std_bpktl = stddev(self.c_bpktl_sqsum,
                                  self.a_total_bvolume,
                                  self.a_total_bpackets) \
            if self.a_total_bpackets > 1 else (0)
        self.a_mean_fiat = self.c_fiat_sum / self.c_fiat_count \
            if self.c_fiat_count > 0 else (0)
        self.a_std_fiat = stddev(self.c_fiat_sqsum,
                                 self.c_fiat_sum,
                                 self.c_fiat_count) \
            if self.c_fiat_count > 1 else (0)
        self.a_mean_biat = self.c_biat_sum / self.c_biat_count \
            if self.c_biat_count > 0 else (0)
        self.a_std_biat = stddev(self.c_biat_sqsum,
                                 self.c_biat_sum,
                                 self.c_biat_count) \
            if self.c_biat_count > 1 else (0)
        self.a_mean_active = self.c_active_time / self.c_active_count \
            if self.c_active_count > 0 else log.debug("ERR: This shouldn't happen")
        self.a_std_active = stddev(self.c_active_sqsum,
                                   self.c_active_time,
                                   self.c_active_count) \
            if self.c_active_count > 1 else (0)
        self.a_mean_idle = self.c_idle_time / self.c_idle_count \
            if self.c_idle_count > 0 else (0)
        self.a_std_idle = stddev(self.c_idle_sqsum,
                                 self.c_idle_time,
                                 self.c_idle_count) \
            if self.c_idle_count > 1 else (0)
        if self.c_active_count > 0:
            self.a_sflow_fpackets = self.a_total_fpackets / self.c_active_count
            self.a_sflow_fbytes = self.a_total_bpackets / self.c_active_count
            self.a_sflow_bpackets = self.a_total_bpackets / self.c_active_count
            self.a_sflow_bbytes = self.a_total_bpackets / self.c_active_count
        self.a_duration = self.get_last_time() - self._first

        export = [
                  self.a_srcip,
                  self.a_srcport,
                  self.a_dstip,
                  self.a_dstport,
                  self.a_proto,
                  self.a_total_fpackets,
                  self.a_total_fvolume,
                  self.a_total_bpackets,
                  self.a_total_bvolume,
                  self.a_min_fpktl,
                  self.a_mean_fpktl,
                  self.a_max_fpktl,
                  self.a_std_fpktl,
                  self.a_min_bpktl,
                  self.a_mean_bpktl,
                  self.a_max_bpktl,
                  self.a_std_bpktl,
                  self.a_min_fiat,
                  self.a_mean_fiat,
                  self.a_max_fiat,
                  self.a_std_fiat,
                  self.a_min_biat,
                  self.a_mean_biat,
                  self.a_max_biat,
                  self.a_std_biat,
                  self.a_duration,
                  # TODO: Possibly need to add the last active time? This is
                  # done in NM l645. Need to confirm whether this is needed for
                  # our implementation. (DA: don't think so) 
                  self.a_min_active,
                  self.a_mean_active,
                  self.a_max_active,
                  self.a_std_active,
                  self.a_min_idle,
                  self.a_mean_idle,
                  self.a_max_idle,
                  self.a_std_idle,
                  self.a_sflow_fpackets,
                  self.a_sflow_fbytes,
                  self.a_sflow_bpackets,
                  self.a_sflow_bbytes,
                  self.a_fpsh_cnt,
                  self.a_bpsh_cnt,
                  self.a_furg_cnt,
                  self.a_burg_cnt,
                  self.a_total_fhlen,
                  self.a_total_bhlen
                  ]
        return '(' + ','.join(map(str, export)) + ')'

    def update_tcp_state(self, pkt):
        '''
        Updates the TCP connection state
        
        Checks to see if a valid TCP connection has been made. The function uses
        a finite state machine implemented through the TCP_STATE class and its 
        sub-classes.
        
        Args:
            pkt - the packet to be analyzed to update the TCP connection state
                  for the flow.
        '''
        flags = pkt.sprintf("%TCP.flags%")
        # Update client state
        self._cstate = self._cstate.update(flags, "f", self._pdir)
        log.debug("Updating TCP connection cstate to %s" % (self._cstate))
        # Update server state
        self._sstate = self._sstate.update(flags, "b", self._pdir)
        log.debug("Updating TCP connection sstate to %s" % (self._sstate))

    def update_status(self, pkt):
        '''
        Updates the status of a flow, checking if the flow is a valid flow.
        
        In the case of UDP, this is a simple check upon whether at least one
        packet has been sent in each direction.
        
        In the case of TCP, the validity check is a little more complex. A valid
        TCP flow requires that a TCP connection is established in the usual way.
        Furthermore, the TCP flow is terminated when a TCP connection is closed,
        or upon a timeout defined by FLOW_TIMEOUT.
        
        Args:
            pkt - the packet to be analyzed for updating the status of the flow.
        '''
        if pkt.proto == 19:
            # UDP
            # Skip if already labelled valid
            if self._valid: return
            # Check if a packet has been received from backward direction. One
            # packet has already been sent in forward direction to initiate.
            if pkt.len > 8:
                # TODO: Check for 1 packet in each direction
                self._valid = True
        elif pkt.proto == 6:
            # TCP
            if isinstance(self._cstate, TCP_ESTABLISHED):
                hlen, _, _ = self.get_header_lengths(pkt)
                if pkt.len > hlen:
                    #TODO: Why would we need a hasdata variable such as in NM?
                    self._valid = True
            if not self._valid:
                #Check validity
                pass
            self.update_tcp_state(pkt)
        else:
            raise NotImplementedError

    def get_last_time(self):
        '''
        Returns the time stamp of the most recent packet in the flow, be it the
        last packet in the forward direction, or the last packet in the backward
        direction.
        
        Reimplementation of the NetMate flowstats method 
        getLast(struct flowData_t). 
        
        Returns:
            The timestamp of the last packet.
        '''
        if (self._blast == 0):
            return self._flast
        elif (self._flast == 0):
            return self._blast
        else:
            return self._flast if (self._flast > self._blast) else self._blast

    def get_header_lengths(self, pkt):
        '''
        Returns the total header length, as well as the protocol specific header
        and internet protocol header lengths.
        
        Args:
            pkt - The packet for which the header lengths are to be retrieved.
        
        Returns:
            [0] - The total header length.
            [1] - The protocol specific (TCP or UDP) header length.
            [2] - The length of the internet protocol header. 
        '''
        # iphlen - Length of the IP header
        iphlen = pkt[IP].ihl * 32 / 8 # ihl field * 32-bits / 8 bits in a byte
        # protohlen - Length of the protocol specific header.
        if (pkt.proto == 19):
            protohlen = 8
        elif (pkt.proto == 6):
            protohlen = pkt[TCP].dataofs * 32 / 8 # TCPHL * 32 bit word / 8 bits per byte
        # hlen - Total header length
        hlen = iphlen + protohlen
        return hlen, protohlen, iphlen

    def add(self, pkt):
        '''
        Add a packet to the current flow.
        
        This function adds the packet, provided as an argument, to the flow.
        
        Args:
            pkt: The packet to be added
        Returns:
            0 - the packet is successfully added to the flow
            1 - the flow is complete with this packet (ie. TCP connect closed)
            2 - the packet is not part of this flow. (ie. flow timeout exceeded) 
        '''
        # TODO: Robust check of whether or not the packet is part of the flow.
        now = pkt.time
        last = self.get_last_time()
        diff = now - last
        log.debug("NOW: %f LAST: %f DIFF: %f" % (now, last, diff))
        if diff > FLOW_TIMEOUT:
            return 2

        len = pkt.len
        # iphlen - Length of the IP header
        hlen, _, _ = self.get_header_lengths(pkt)
        dscp = pkt[IP].tos >> 2 # Bit shift twice to the right to get DSCP only
                                # TODO: verify this is working correctly.

        assert (now >= self._first)
        # Ignore re-ordered packets
        if (now < last):
            log.debug("Flow: ignoring reordered packet. %d < %d" %
                      (now, last))
            raise NotImplementedError
        # Update the global variable _pdir which holds the direction of the
        # packet currently in question.  
        if (pkt[IP].src == self._first_packet[IP].src):
            self._pdir = "f"
        else:
            self._pdir = "b"
        # Update the status (validity, TCP connection state) of the flow.
        self.update_status(pkt)
        # Set attributes.
        if diff > IDLE_THRESHOLD:
            # The flow has been idle, so calc idle time stats
            if diff > self.a_max_idle:
                self.a_max_idle = diff
            if diff < self.a_min_idle or self.a_min_idle < 0:
                self.a_min_idle = diff
            self.c_idle_time += diff
            self.c_idle_sqsum += (diff ** 2)
            self.c_idle_count += 1
            # Active time stats - calculated by looking at the previous packet
            # time and the packet time for when the last idle time ended.
            diff = last - self.c_active_start
            if diff > self.a_max_active:
                self.a_max_active = diff
            if diff < self.a_min_active or self.a_min_active < 0:
                self.a_min_active = diff
            self.c_active_time += diff
            self.c_active_sqsum += (diff ** 2)
            self.c_active_count += 1
            self._flast = 0
            self._blast = 0
            self.c_active_start = now
        # Set bi-directional attributes.
        if self._pdir == "f":
            # Packet is travelling in the forward direction
            # Calculate some statistics
            # Packet length
            if len < self.a_min_fpktl or self.a_min_fpktl == 0:
                self.a_min_fpktl = len
            if len > self.a_max_fpktl:
                self.a_max_fpktl = len
            self.a_total_fvolume += len # Doubles up as c_fpktl_sum from NM
            self.c_fpktl_sqsum += (len ** 2)
            self.a_total_fpackets += 1
            self.a_total_fhlen += hlen
            # Interarrival time
            if self._flast > 0:
                diff = now - self._flast
                if diff < self.a_min_fiat or self.a_min_fiat == 0:
                    self.a_min_fiat = diff
                if diff > self.a_max_fiat:
                    self.a_max_fiat = diff
                self.c_fiat_sum += diff
                self.c_fiat_sqsum += (diff ** 2)
                self.c_fiat_count += 1
            if pkt.proto == 6:
                # Packet is using TCP protocol
                flags = pkt.sprintf("%TCP.flags%")
                if (tcp_set(flags, "P")):
                    self.a_fpsh_cnt += 1
                if (tcp_set(flags, "U")):
                    self.a_furg_cnt += 1
            # Update the last forward packet time stamp
            self._flast = now
        else:
            # Packet is travelling in the backward direction
            # Calculate some statistics
            # Packet length
            if len < self.a_min_bpktl or self.a_min_bpktl == 0:
                self.a_min_bpktl = len
            if len > self.a_max_bpktl:
                self.a_max_bpktl = len
            self.a_total_bvolume += len # Doubles up as c_bpktl_sum from NM
            self.c_bpktl_sqsum += (len ** 2)
            self.a_total_bpackets += 1
            self.a_total_bhlen += hlen
            # Interarrival time
            if self._blast > 0:
                diff = now - self._blast
                if diff < self.a_min_biat or self.a_min_biat == 0:
                    self.a_min_biat = diff
                if diff > self.a_max_biat:
                    self.a_max_biat = diff
                self.c_biat_sum += diff
                self.c_biat_sqsum += (diff ** 2)
                self.c_biat_count += 1
            if pkt.proto == 6:
                # Packet is using TCP protocol
                flags = pkt.sprintf("%TCP.flags%")
                if (tcp_set(flags, "P")):
                    self.a_bpsh_cnt += 1
                if (tcp_set(flags, "U")):
                    self.burg_cnt += 1
            # Update the last backward packet time stamp
            self._blast = now
        #((proto == 6) && (data->cstate == STATE_CLOSED) && (data->sstate == STATE_CLOSED))
        if (pkt.proto == 6 and
            isinstance(self._cstate, TCP_CLOSED) and
            isinstance(self._sstate, TCP_CLOSED)):
            return 1
        else:
            return 0
#--------------------------------------------------------------------- End: Flow
