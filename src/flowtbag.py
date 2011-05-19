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
from Flow import Flow

def sort_by_IP(self, t):
    if (t[2] < t[0]):
        new_tuple = (t[2], t[3], t[0], t[1], t[4])
    else:
        new_tuple = t
    return new_tuple

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
        flow_tuple = sort_by_IP(flow_tuple)

        if (pkt.proto == 6):
            # TCP
            if (flow_tuple not in self.active_flows):
                self.flow_count += 1
                self.active_flows[flow_tuple] = Flow(pkt, self.flow_count)
                print "Created flow %d" % (self.flow_count)
            else:
                print "Adding packet %d to flow %s" % \
                    (self.count, self.active_flows[flow_tuple])
                self.active_flows[flow_tuple].add_to_flow(pkt)
            #print "%s" % (flow_tuple,)
            #print "TCP Flags: %s" % (pkt[TCP].flags)
            #flags=pkt.sprintf("%TCP.flags%")
            #print "%s" % (flags)
        elif (pkt.proto == 17):
            # UDP
            print "UDP: [SPort %s | DPort %s]" % \
                (pkt.sport, pkt.dport)

if __name__ == '__main__':
    Flowtbag()
