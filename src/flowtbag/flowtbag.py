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
import time
import binascii as ba
import socket
import struct

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pcap
from flow import Flow

#Set up default logging system.
log = logging.getLogger()
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s;%(levelname)s:: "
                              "%(message)s :: %(filename)s:%(lineno)s",
                              "%H:%M:%S")
ch.setFormatter(formatter)
log.addHandler(ch)

REPORT_INTERVAL = 500000

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
            # Set up pylibpcap
            pcap_reader = pcap.pcapObject()
            pcap_reader.open_offline(filename)
#            pcap_reader.setfilter('(tcp or udp)', 0, 0)
            pcap_reader.loop(-1,self.callback)
            self.exportAll()
        except KeyboardInterrupt:
            self.exportAll()
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
        count = 0
        for flow_tuple in self.active_flows.keys():
            flow = self.active_flows[flow_tuple]
            if flow.checkidle(time):
                flow.export()
                del self.active_flows[flow_tuple]
                count += 1
        log.info("Cleaned up %d idle flows" % count)

    def decode_IP_layer(self, data, pkt):
        pkt['version'] = (ord(data[0]) & 0xf0) >> 4
        pkt['iphlen']  = (ord(data[0]) & 0x0f) * 4
        pkt['dscp']    = ord(data[1]) >> 2
        pkt['len']     = socket.ntohs(struct.unpack('H',data[2:4])[0])
        pkt['proto']   = ord(data[9])
        pkt['srcip']   = pcap.ntoa(struct.unpack('i',data[12:16])[0])
        pkt['dstip']   = pcap.ntoa(struct.unpack('i',data[16:20])[0])
        pkt['data']    = data[pkt['iphlen']:]

    def decode_TCP_layer(self, data, pkt):
        pkt['srcport'] = socket.ntohs(struct.unpack('H', data[0:2])[0])
        pkt['dstport'] = socket.ntohs(struct.unpack('H', data[2:4])[0])
        pkt['prhlen']  = ((ord(data[12]) & 0xf0) >> 4) * 4
        pkt['flags'] = ord(data[13]) & 0x3f

    def decode_UDP_layer(self, data, pkt):
        pkt['srcport'] = socket.ntohs(struct.unpack('H', data[0:2])[0])
        pkt['dstport'] = socket.ntohs(struct.unpack('H', data[2:4])[0])
        pkt['prhlen']  = socket.ntohs(struct.unpack('H', data[4:6])[0])

    def callback(self, pktlen, data, ts):
        '''
        The callback function to be used to process each packet
        
        This function is applied to each individual packet in the capture via a 
        loop function in the construction of the Flowtbag.
        
        Args:
            pktlen -- The length of the packet
            data -- The packet payload
            ts -- The timestamp of the packet
        '''
        self.count += 1
        if not data:
            # I don't know when this happens, so I wanna know.
            raise Exception
        log.debug("Processing packet %d" % self.count)
        if self.count % REPORT_INTERVAL == 0:
            self.end_time_interval = time.clock()
            self.elapsed = self.end_time_interval - self.start_time_interval
            log.info("Processed %d packets. Timestamp %f" % 
                     (self.count, ts))
            log.info("Took %f s to process %d packets" % 
                     (self.elapsed, REPORT_INTERVAL))
            log.info("Current size of the flowtbag: %d" % 
                     len(self.active_flows))
            self.start_time_interval = self.end_time_interval
            self.cleanup_active(ts)
        #log.debug("IP field: %s" % ba.hexlify(data[12:14]))
        pkt={}
        # Check if the packet is an IP packet
        if not data[12:14] == '\x08\x00':
            log.debug('Ignoring non-IP packet')
            return
        self.decode_IP_layer(data[14:], pkt)
        if pkt['version'] != 4:
            log.debug('Ignoring non-IPv4 packet')
            return
        if pkt['proto'] == 6:
            self.decode_TCP_layer(pkt['data'], pkt)
        elif pkt['proto'] == 17:
            self.decode_UDP_layer(pkt['data'], pkt)
        else:
            log.debug('Ignoring non-TCP/UDP packet')
            return
        # We're really going ahead with this packet! Let's get 'er done.
        pkt['time'] = ts

        log.debug("type: %d prhlen: %d len: %d" % 
                  (pkt['proto'], pkt['prhlen'], pkt['len']))
        
        flow_tuple = (pkt['srcip'],
                      pkt['srcport'], 
                      pkt['dstip'], 
                      pkt['dstport'], 
                      pkt['proto'])
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
