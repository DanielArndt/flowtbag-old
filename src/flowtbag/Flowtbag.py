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

import sys
import argparse
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Flow import Flow

#Set up default logging system.
log = logging.getLogger()
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s;%(levelname)s:: %(message)s :: %(filename)s:%(lineno)s",
                              "%H:%M:%S")
ch.setFormatter(formatter)
log.addHandler(ch)

REPORT_INTERVAL = 10000

def sort_by_IP(t):
    '''
    Re-arrange a flow tuple to have lowest IP first, for lookup
    '''
    return (t[2], t[3], t[0], t[1], t[4]) if t[2] < t[0] else t

class Flowtbag:
    '''
    classdocs
    '''
    def __init__(self, filename="test.cap"):
        try:
            self.count = 0
            self.flow_count = 0
            self.active_flows = {}
            self.start_time_interval = 0.0
            sniff(offline=filename, prn=self.callback, store=0)
            self.exportAll()
        except KeyboardInterrupt:
            exit(0)

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        return "I am a Flowtbag of size %s" % (len(self.active_flows))

    def exportAll(self):
        for flow in self.active_flows.values():
            flow.export()

    def create_flow(self, pkt, flow_tuple):
        self.flow_count += 1
        flow = Flow(pkt, self.flow_count)
        self.active_flows[flow_tuple] = flow

    def cleanup_active(self, time):
        for flow_tuple in self.active_flows.keys():
            flow = self.active_flows[flow_tuple]
            if flow.checkidle(time):
                flow.export()
                del self.active_flows[flow_tuple]
                

    def callback(self, pkt):
        '''
        The callback function to be used to process each packet
        
        This function is applied to each individual packet in the capture.
        
        Args:
            pkt: The packet to be processed
        '''
        self.count += 1
        if self.count % REPORT_INTERVAL == 0:
            self.end_time_interval = time.clock()
            self.elapsed = self.end_time_interval - self.start_time_interval
            log.info("Processed %d packets." % self.count)
            log.info("Took %f s to process %d packets" % (self.elapsed,
                                                          REPORT_INTERVAL))
            log.info("Current size of the flowtbag: %d" % len(self.active_flows))
            self.start_time_interval = self.end_time_interval
            self.cleanup_active(pkt.time)
        if IP not in pkt or pkt.proto not in (6, 19):
            # Ignore non-IP packets or packets that aren't TCP or UDP
            return
        srcip = pkt[IP].src
        srcport = pkt.sport
        dstip = pkt[IP].dst
        dstport = pkt.dport
        proto = pkt.proto
        flow_tuple = (srcip, srcport, dstip, dstport, proto)
        flow_tuple = sort_by_IP(flow_tuple)
        # Find if a flow already exists for this tuple
        if flow_tuple not in self.active_flows:
            # The a flow of this tuple does not exists yet, create it.
            self.create_flow(pkt, flow_tuple)
        else:
            # A flow of this tuple already exists, add to it.
            flow = self.active_flows[flow_tuple]
            return_val = flow.add(pkt)
            if return_val == 0:
                return
            elif return_val == 1:
                #This packet ended the TCP connection. Export it.
                flow.export()
                del self.active_flows[flow_tuple]
            elif return_val == 2:
                # This packet has been added to the wrong flow. This means the 
                # previous flow has ended. We export the old flow, remove it,
                # and create a new flow.
                flow.export()
                del self.active_flows[flow_tuple]
                self.create_flow(pkt, flow_tuple)

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Converts a network capture '\
        'file into a comma seperated value list of integers representing ' \
        'a list of flow statistics.')
    arg_parser.add_argument('capture_file',
                            help='The capture file to be converted')
    arg_parser.add_argument('--debug',
                            dest='debug',
                            action='store_true',
                            default=False,
                            help='display debugging information')
    arg_parser.add_argument('-r',
                            dest='report',
                            type=int,
                            default=10000,
                            help='interval (num pkts) which stats be reported')
    args = arg_parser.parse_args()
    log.debug("Flowtbag begin")
    if args.report:
        REPORT_INTERVAL = args.report
    if args.debug:
        log.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    Flowtbag(args.capture_file)
    log.debug("Flowtbag end")
