# Copyright (C) 2014 High Speed Network Labtory, Polytechnic School of Engineering, NYU
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER , HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import mac
from ryu.lib import ip
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu import utils
import struct
import random

class CABSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CABSwitch, self).__init__(*args, **kwargs)
        self.overflow_cnt = 0
        self.is_overflow = False
        self.queries = 0
        self.packetin = 0
        self.packetout = 0
        self.flowmod = 0
        self.query_map = {}
        self.tracefile = raw_input('Enter Tracename: ')
        # open('./results/packetin_cem'+self.tracefile, 'w').close()
        # open('./results/queries_cem'+self.tracefile, 'w').close()


    def add_flow(self, datapath, table_id, priority, match, inst,buffer_id,hard_timeout = 60):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,hard_timeout=hard_timeout, table_id = table_id, priority=priority, match=match, instructions=inst, buffer_id = buffer_id)
        datapath.send_msg(mod)
        self.flowmod += 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        self.logger.info('OFPSwitchFeatures datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities))
        # First, clear table entries
        mod = parser.OFPFlowMod(datapath=datapath,command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)
        #set table0 default rule: go to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst, ofproto.OFP_NO_BUFFER,0)

        m = threading.Thread(target=self.monitor)
        m.start()
        c = threading.Thread(target=self.clean_query_map)
        c.start()

    @set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s', msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packetin += 1      
        msg = ev.msg
        in_port = msg.match['in_port']

        #datapath is the object which denotes the link between switch and controller
        datapath = msg.datapath
        dpid = datapath.id
        
        #ofproto and parser is version related
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
       
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                self.overflow_cnt += 1
                if self.is_overflow == False:
                    # logger.warning('warning\tswitch packet-in overflow %d', self.overflow_cnt)
                    is_overflow = True
        else:
            is_overflow = False
        #msg.data is raw data.
        pkt = packet.Packet(msg.data)
        #header class: http://ryu.readthedocs.org/en/latest/library_packet_ref.html
        
        #parse ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_dst = eth.dst
        eth_src = eth.src
        ethertype = eth.ethertype       

        if ethertype == ether.ETH_TYPE_ARP:
            self.send_packet_out(datapath,msg,in_port)
            return

        if ethertype == ether.ETH_TYPE_IP:
            self.handle_ip(datapath,msg,in_port)
            return 

    def handle_no_buffer(self, datapath, data, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(3)]
        req = ofp_parser.OFPPacketOut(datapath, ofp.OFP_NO_BUFFER, in_port, actions, data)
        datapath.send_msg(req)
        self.packetout += 1

    def send_packet_out(self, datapath, msg, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)
        else:
            actions = [ofp_parser.OFPActionOutput(3)]
            req = ofp_parser.OFPPacketOut(datapath, msg.buffer_id, in_port, actions)
            datapath.send_msg(req)

    def handle_ping(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)#
        match.set_ip_proto(inet.IPPROTO_ICMP)#
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        self.add_flow(datapath, 0, 200, match, inst, msg.buffer_id, 1)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath,msg.data,in_port)

    def handle_ip(self,datapath,msg,in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        #try to parse ip header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_dst = eth.dst
        eth_src = eth.src
        ip_header = pkt.get_protocol(ipv4.ipv4)
        ip_src = ip_header.src
        ip_dst = ip_header.dst

        # key = ip_src+'\t'+ip_dst+'\t'+eth_src+'\t'+eth_dst
        # with open('./results/packetin_cem'+self.tracefile, 'a') as ff:
        #     string = str(time.time())+'\t'+key+'\n'
        #     ff.write(string)

        #try to parse icmp
        if ip_header.proto == inet.IPPROTO_ICMP:
            self.handle_ping(datapath, msg, in_port)
            return

        if ip_header.proto != inet.IPPROTO_TCP:
            self.send_packet_out(datapath,msg,in_port)
            return

        key = ip_src+'\t'+ip_dst+'\t'+eth_src+'\t'+eth_dst

        #if not the fisrt packet of the flow, don't query CAB
        if key in self.query_map:
            self.send_packet_out(datapath,msg,in_port)
            return
        self.query_map[key] = time.time()

        self.queries += 1

        # with open('./results/queries_cem'+self.tracefile, 'a') as fq:
        #     string = str(time.time())+'\t'+key+'\n'
        #     fq.write(string)

        timeout = random.randint(20,30)

        #install Exact Match Rule
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_src=eth_src, eth_dst=eth_dst)

        actions = [parser.OFPActionOutput(3)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        self.add_flow(datapath,0,100,match,inst,msg.buffer_id,timeout)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)

        self.logger.debug( "install EM %s %s %s %s", ip_src, ip_dst, eth_src, eth_dst)


    def monitor(self):
        with open('./results/results_cem_'+self.tracefile, 'w') as f:
            f.write('time\tqueries\tPacketIn\tFlowMod\n')
            while True:
                string = str(time.time())+'\t'+str(self.queries)+'\t'+str(self.packetin)+'\t'+str(self.flowmod)+'\n'
                f.write(string)

                time.sleep(1)

    def clean_query_map(self):
        while True:
            time.sleep(10)
            for i in self.query_map.keys():
                if (time.time() - self.query_map[i]) > 8 :
                    del self.query_map[i]

