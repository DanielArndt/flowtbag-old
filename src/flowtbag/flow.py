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
import logging
import math
import sys, traceback

# PLEASE READ tcp_set.py BEFORE READING THIS SOURCE, AS IT IS IMPORTED
# DIRECTLY INTO THIS NAMESPACE FOR CONVIENCE.
from tcp_state import *

# Retrieve the default logger, should have been initialized by the Flowtbag.
log = logging.getLogger()

#---------------------------------------------------------------------- Settings
FLOW_TIMEOUT = 600000000 # Flow timeout in seconds 
IDLE_THRESHOLD = 1000000
#----------------------------------------------------------------- End: Settings

def stddev(sqsum, sum, count):
    return int(math.sqrt((sqsum - (sum ** 2 / count)) / (count - 1)))

#==============================================================================#
# Begin code for Flow class                                                    #
#==============================================================================#
features = [
    'srcip',
    'srcport',
    'dstport',
    'proto',
    'total_fpackets',
    'total_fvolume',
    'total_bpackets',
    'total_bvolume',
    'min_fpktl',
    'mean_fpktl',
    'max_fpktl',
    'std_fpktl',
    'min_bpktl',
    'mean_bpktl',
    'max_bpktl',
    'std_bpktl',
    'min_fiat',
    'mean_fiat',
    'max_fiat',
    'std_fiat',
    'min_biat',
    'mean_biat',
    'max_biat',
    'std_biat',
    'duration',
    'min_active',
    'mean_active',
    'max_active',
    'std_active',
    'min_idle',
    'mean_idle',
    'max_idle',
    'std_idle',
    'sflow_fpackets',
    'sflow_fbytes',
    'sflow_bpackets',
    'sflow_bbytes',
    'fpsh_cnt',
    'bpsh_cnt',
    'furg_cnt',
    'burg_cnt',
    'total_fhlen',
    'total_bhlen',
    'dscp'
    ]

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

        d_ - Variables used for debugging output.
    
    '''
    def __init__(self, pkt, id):
        '''
        Constructor. Initialize all values.
        '''
        if log.isEnabledFor(logging.DEBUG):
            self.d_packets = [pkt['num']]
        # Set initial values
        self._id = id
        self._first_packet = pkt
        self._valid = False
        self._pdir = "f"
        self._first = pkt['time']
        self._flast = pkt['time']
        self._blast = 0
        self.f = { x:0 for x in features }
        #------------------------------------ Basic flow identification criteria
        self.f['srcip'] = pkt['srcip']
        self.f['srcport'] = pkt['srcport']
        self.f['dstip'] = pkt['dstip']
        self.f['dstport'] = pkt['dstport']
        self.f['proto'] = pkt['proto']
        self.f['dscp'] = pkt['dscp']
        #--------------------------------------------------------------------- #
        self.f['total_fpackets'] = 1
        self.f['total_fvolume'] = pkt['len']
        self.f['min_fpktl'] = pkt['len']
        self.f['max_fpktl'] = pkt['len']
        self.c_fpktl_sqsum = (pkt['len'] ** 2)
        self.c_bpktl_sqsum = 0
        self.c_fiat_sum = 0
        self.c_fiat_sqsum = 0
        self.c_fiat_count = 0
        self.c_biat_sum = 0
        self.c_biat_sqsum = 0
        self.c_biat_count = 0
        self.c_active_start = self._first
        self.c_active_time = 0
        self.c_active_sqsum = 0
        self.c_active_count = 0
        self.c_idle_time = 0
        self.c_idle_sqsum = 0
        self.c_idle_count = 0
        if pkt['proto'] == 6:
            # TCP specific
            # Create state machines for the client and server 
            self._cstate = STATE_TCP_START() # Client state
            self._sstate = STATE_TCP_START() # Server state
            # Set TCP flag stats
            if (tcp_set(pkt['flags'], TCP_PSH)):
                self.f['fpsh_cnt'] = 1
            if (tcp_set(pkt['flags'], TCP_URG)):
                self.f['furg_cnt'] = 1
        self.f['total_fhlen'] = pkt['iphlen'] + pkt['prhlen']
        self.update_status(pkt)

    def __repr__(self):
        return "[%d:(%s,%d,%s,%d,%d)]" % \
            (self._id, 
             self.f['srcip'], 
             self.f['srcport'], 
             self.f['dstip'],
             self.f['dstport'], 
             self.f['proto'])

    def __str__(self):
        '''
        Exports the stats collected.
        '''
        # Count the last active time
        diff = self.get_last_time() - self.c_active_start
        if diff > self.f['max_active']:
            self.f['max_active'] = diff
        if (diff < self.f['min_active'] or 
            self.f['min_active'] == 0
            ):
            self.f['min_active'] = diff
        self.c_active_time += diff
        self.c_active_sqsum += (diff ** 2)
        self.c_active_count += 1

        assert(self.f['total_fpackets'] > 0)
        self.f['mean_fpktl'] = \
            self.f['total_fvolume'] / self.f['total_fpackets']
        # Standard deviation of packets in the forward direction
        if self.f['total_fpackets'] > 1:
            self.f['std_fpktl'] = stddev(self.c_fpktl_sqsum,
                                         self.f['total_fvolume'],
                                         self.f['total_fpackets'])
        else:
            self.f['std_fpktl'] = 0
        # Mean packet length of packets in the packward direction
        if self.f['total_bpackets'] > 0:
            self.f['mean_bpktl'] = \
                self.f['total_bvolume'] / self.f['total_bpackets']
        else:
            self.f['mean_bpktl'] = -1
        # Standard deviation of packets in the backward direction
        if self.f['total_bpackets'] > 1:
            self.f['std_bpktl'] = stddev(self.c_bpktl_sqsum,
                                         self.f['total_bvolume'],
                                         self.f['total_bpackets'])
        else:
            self.f['std_bpktl'] = 0
        # Mean forward inter-arrival time
        # TODO: Check if we actually need c_fiat_count ?
        if self.c_fiat_count > 0:
            self.f['mean_fiat'] = self.c_fiat_sum / self.c_fiat_count
        else:
            self.f['mean_fiat'] = 0
        # Standard deviation of forward inter-arrival times
        if self.c_fiat_count > 1:
            self.f['std_fiat'] = stddev(self.c_fiat_sqsum,
                                        self.c_fiat_sum,
                                        self.c_fiat_count)
        else:
            self.f['std_fiat'] = 0
        # Mean backward inter-arrival time
        if self.c_biat_count > 0:
            self.f['mean_biat'] = self.c_biat_sum / self.c_biat_count
        else:
            self.f['mean_biat'] = 0
        # Standard deviation of backward inter-arrival times
        if self.c_biat_count > 1:
            self.f['std_biat'] = stddev(self.c_biat_sqsum,
                                        self.c_biat_sum,
                                        self.c_biat_count)
        else:
            self.f['std_biat'] = 0
        # Mean active time of the sub-flows
        if self.c_active_count > 0:
            self.f['mean_active'] = self.c_active_time / self.c_active_count
        else:
            # There should be packets in each direction if we're exporting 
            log.debug("ERR: This shouldn't happen")
            raise Exception
        # Standard deviation of active times of sub-flows
        if self.c_active_count > 1:
            self.f['std_active'] = stddev(self.c_active_sqsum,
                                          self.c_active_time,
                                          self.c_active_count)
        else:
            self.f['std_active'] = 0
        # Mean of idle times between sub-flows
        if self.c_idle_count > 0:
            self.f['mean_idle'] = self.c_idle_time / self.c_idle_count
        else:
            self.f['mean_idle'] = 0
        # Standard deviation of idle times between sub-flows
        if self.c_idle_count > 1:
            self.f['std_idle'] = stddev(self.c_idle_sqsum,
                                        self.c_idle_time,
                                        self.c_idle_count)
        else:
            self.f['std_idle'] = 0
        # More sub-flow calculations
        if self.c_active_count > 0:
            self.f['sflow_fpackets'] = \
                self.f['total_fpackets'] / self.c_active_count
            self.f['sflow_fbytes'] = \
                self.f['total_fvolume'] / self.c_active_count
            self.f['sflow_bpackets'] = \
                self.f['total_bpackets'] / self.c_active_count
            self.f['sflow_bbytes'] = \
                self.f['total_bvolume'] / self.c_active_count
        self.f['duration'] = self.get_last_time() - self._first
        assert (self.f['duration'] >= 0)

        export = [
                  self.f['srcip'],
                  self.f['srcport'],
                  self.f['dstip'],
                  self.f['dstport'],
                  self.f['proto'],
                  self.f['total_fpackets'],
                  self.f['total_fvolume'],
                  self.f['total_bpackets'],
                  self.f['total_bvolume'],
                  self.f['min_fpktl'],
                  self.f['mean_fpktl'],
                  self.f['max_fpktl'],
                  self.f['std_fpktl'],
                  self.f['min_bpktl'],
                  self.f['mean_bpktl'],
                  self.f['max_bpktl'],
                  self.f['std_bpktl'],
                  self.f['min_fiat'],
                  self.f['mean_fiat'],
                  self.f['max_fiat'],
                  self.f['std_fiat'],
                  self.f['min_biat'],
                  self.f['mean_biat'],
                  self.f['max_biat'],
                  self.f['std_biat'],
                  self.f['duration'],
                  self.f['min_active'],
                  self.f['mean_active'],
                  self.f['max_active'],
                  self.f['std_active'],
                  self.f['min_idle'],
                  self.f['mean_idle'],
                  self.f['max_idle'],
                  self.f['std_idle'],
                  self.f['sflow_fpackets'],
                  self.f['sflow_fbytes'],
                  self.f['sflow_bpackets'],
                  self.f['sflow_bbytes'],
                  self.f['fpsh_cnt'],
                  self.f['bpsh_cnt'],
                  self.f['furg_cnt'],
                  self.f['burg_cnt'],
                  self.f['total_fhlen'],
                  self.f['total_bhlen'],
                  self.f['dscp']
                  ]
        return ','.join(map(str, export))
        
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
        # Update client state
        self._cstate = self._cstate.update(pkt['flags'], "f", self._pdir)
        # Update server state
        self._sstate = self._sstate.update(pkt['flags'], "b", self._pdir)

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
        if pkt['proto'] == 17:
            # UDP
            # Skip if already labelled valid
            if self._valid: return
            # If packet length is over 8 (size of a UDP header), then we have
            # at least one byte of data
            if pkt['len'] > 8:
                self.has_data = True
            if self.has_data and self.f['total_bpackets'] > 0:
                self._valid = True
        elif pkt['proto'] == 6:
            # TCP
            if isinstance(self._cstate, STATE_TCP_ESTABLISHED):
                hlen = pkt['iphlen'] + pkt['prhlen']
                if pkt['len'] > hlen:
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

    def dumpFlow(self):
        '''
        Dumps a flow, regardless of status.

        Dumps all a flow's contents for debugging purposes.
        '''
        log.error("Dumping flow to flow_dump")

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
        now = pkt['time']
        last = self.get_last_time()
        diff = now - last
        if diff > FLOW_TIMEOUT:
            return 2
        # Ignore re-ordered packets
        if (now < last):
            log.info("Flow: ignoring reordered packet. %d < %d" %
                      (now, last))
            return 0
            #raise NotImplementedError
        # Add debugging info
#        if log.isEnabledFor(logging.DEBUG):
#            self.d_packets.append(pkt['num'])
        # OK - we're serious about this packet. Lets add it.
        #Gather some statistics
        len = pkt['len']
        hlen = pkt['iphlen'] + pkt['prhlen']
        assert (now >= self._first)
        # Update the global variable _pdir which holds the direction of the
        # packet currently in question.  
        if (pkt['srcip'] == self._first_packet['srcip']):
            self._pdir = "f"
        else:
            self._pdir = "b"
        # Set attributes.
        if diff > IDLE_THRESHOLD:
            # The flow has been idle previous to this packet, so calc idle time 
            # stats
            if diff > self.f['max_idle']:
                self.f['max_idle'] = diff
            if (diff < self.f['min_idle'] or 
                self.f['min_idle'] == 0
                ):
                self.f['min_idle'] = diff
            self.c_idle_time += diff
            self.c_idle_sqsum += (diff ** 2)
            self.c_idle_count += 1
            # Active time stats - calculated by looking at the previous packet
            # time and the packet time for when the last idle time ended.
            diff = last - self.c_active_start
            if diff > self.f['max_active']:
                self.f['max_active'] = diff
            if diff < self.f['min_active'] or self.f['min_active'] == 0:
                self.f['min_active'] = diff
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
            if len < self.f['min_fpktl'] or self.f['min_fpktl'] == 0:
                self.f['min_fpktl'] = len
            if len > self.f['max_fpktl']:
                self.f['max_fpktl'] = len
            self.f['total_fvolume'] += len # Doubles up as c_fpktl_sum from NM
            self.c_fpktl_sqsum += (len ** 2)
            self.f['total_fpackets'] += 1
            self.f['total_fhlen'] += hlen
            # Interarrival time
            if self._flast > 0:
                diff = now - self._flast
                if diff < self.f['min_fiat'] or self.f['min_fiat'] == 0:
                    self.f['min_fiat'] = diff
                if diff > self.f['max_fiat']:
                    self.f['max_fiat'] = diff
                self.c_fiat_sum += diff
                self.c_fiat_sqsum += (diff ** 2)
                self.c_fiat_count += 1
            if pkt['proto'] == 6:
                # Packet is using TCP protocol
                if (tcp_set(pkt['flags'], TCP_PSH)):
                    self.f['fpsh_cnt'] += 1
                if (tcp_set(pkt['flags'], TCP_URG)):
                    self.f['furg_cnt'] += 1
            # Update the last forward packet time stamp
            self._flast = now
        else:
            # Packet is travelling in the backward direction, check if dscp is
            # set in this direction
            if self._blast == 0 and self.f['dscp'] == 0:
                # Check only first packet in backward dir, and make sure it has
                # not been set already.
                self.f['dscp'] = pkt['dscp']
            # Calculate some statistics
            # Packet length
            if len < self.f['min_bpktl'] or self.f['min_bpktl'] == 0:
                self.f['min_bpktl'] = len
            if len > self.f['max_bpktl']:
                self.f['max_bpktl'] = len
            self.f['total_bvolume'] += len # Doubles up as c_bpktl_sum from NM
            self.c_bpktl_sqsum += (len ** 2)
            self.f['total_bpackets'] += 1
            self.f['total_bhlen'] += hlen
            # Inter-arrival time
            if self._blast > 0:
                diff = now - self._blast
                if diff < self.f['min_biat'] or self.f['min_biat'] == 0:
                    self.f['min_biat'] = diff
                if diff > self.f['max_biat']:
                    self.f['max_biat'] = diff
                self.c_biat_sum += diff
                self.c_biat_sqsum += (diff ** 2)
                self.c_biat_count += 1
            if pkt['proto'] == 6:
                # Packet is using TCP protocol
                if (tcp_set(pkt['flags'], TCP_PSH)):
                    self.f['bpsh_cnt'] += 1
                if (tcp_set(pkt['flags'], TCP_URG)):
                    self.f['burg_cnt'] += 1
            # Update the last backward packet time stamp
            self._blast = now

        # Update the status (validity, TCP connection state) of the flow.
        self.update_status(pkt)            

        if (pkt['proto'] == 6 and
            isinstance(self._cstate, STATE_TCP_CLOSED) and
            isinstance(self._sstate, STATE_TCP_CLOSED)):
            return 1
        else:
            return 0
    
    def checkidle(self, time):
        return True if time - self.get_last_time() > FLOW_TIMEOUT else False
        
    def export(self):
        if self._valid:
            try:
                print self
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                log.error("Error printing flow %d which starts with packet %d" %
                          (self._id, self._first_packet['num']))
                log.error("First packet: %f Last: %f" % 
                          (self._first, self.get_last_time()))
                log.error(repr(traceback.format_exception(exc_type, 
                                                          exc_value, 
                                                          exc_traceback)))
                raise e
#--------------------------------------------------------------------- End: Flow
