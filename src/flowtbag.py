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
import logging
from Flow import Flow

#Set up logging system.
log = logging.getLogger()
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s;%(levelname)s:%(message)s",
                              "%H:%M:%S")
ch.setFormatter(formatter)
log.addHandler(ch)


def sort_by_IP(t):
    """
    Re-arrange a flow tuple to have lowest IP first, for lookup
    """
    return (t[2], t[3], t[0], t[1], t[4]) if t[2] < t[0] else t

class Flowtbag:
    """
    classdocs
    """
    def __init__(self, filename="test.cap"):
        try:
            self.count = 0
            self.flow_count = 0
            self.active_flows = {}
            sniff(offline=filename, prn=self.callback, store=0)
        except KeyboardInterrupt:
            exit(0)

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        return "I am a flowtbag of size %s" % (len(self.active_flows))

    def callback(self, pkt):
        """The callback function to be used to process each packet
        
        This is the function applied to each individual packet in the capture. 
        
        Args:
            pkt: The packet to be processed
        """
        self.count += 1
        if IP not in pkt or pkt.proto not in (6, 19):
            # Ignore non-IP packets or packets that aren't TCP or UDP
            log.debug("Ignoring non-IP/TCP/UDP packet %d" % (self.count))
            return
        log.debug("Processing packet %d" % (self.count))
        srcip = pkt[IP].src
        srcport = pkt.sport
        dstip = pkt[IP].dst
        dstport = pkt.dport
        proto = pkt.proto
        flow_tuple = (srcip, srcport, dstip, dstport, proto)
        flow_tuple = sort_by_IP(flow_tuple)
        if flow_tuple not in self.active_flows:
            self.flow_count += 1
            self.active_flows[flow_tuple] = Flow(pkt, self.flow_count)
            log.debug("Created flow %s" % (self.active_flows[flow_tuple]))
        else:
            flow = self.active_flows[flow_tuple]
            log.debug("Adding packet %d to flow %s" % \
                (self.count, repr(flow)))
            flow.add_to_flow(pkt)
            log.debug("At: %s" % (flow))

if __name__ == '__main__':
    Flowtbag()
