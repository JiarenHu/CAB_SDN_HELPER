# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
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
import struct
from cab_client import *

class CABSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CABSwitch, self).__init__(*args, **kwargs)
        self.cab = cab_client()
        self.cab.create_connection()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        self.logger.info('OFPSwitchFeatures datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities))
        #setdefault rule: go to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst)

    def add_flow(self, datapath, table_id, priority, match, inst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,hard_timeout=20, table_id = table_id, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg

        #datapath is the object which denotes the link between switch and controller
        datapath = msg.datapath
        dpid = datapath.id
        
        #ofproto and parser is version related
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
       
        data = None;
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

        #msg.data is raw data.
        pkt = packet.Packet(msg.data)
        #header class: http://ryu.readthedocs.org/en/latest/library_packet_ref.html
        
        #parse ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_dst = eth.dst
        eth_src = eth.src
        ethertype = eth.ethertype

        #try to parse ip header
        ip_header = pkt.get_protocol(ipv4.ipv4)
        self.logger.debug('ip src %s dst %s', ip_header.src, ip_header.dst)
        ip_src = ip_header.src
        ip_dst = ip_header.dst
        
        #try to pars tcp header
        #tcp_header = pkt.get_protocol(tcp.tcp)
        #src_port = tcp_header.src_port
        #dst_port = tcp_header.dst_port
        src_port = 0
        dst_port = 0
        request = pkt_h(ipv4_to_int(ip_src),ipv4_to_int(ip_dst), src_port, dst_port)
        rules = self.cab.query(request)
        if rules == None:
            self.logger.error("request rules for packet failed: %s %s",ip_src,ip_dst)
            return
        #first install rules, rules[0] is bucket
        for rule in rules[1:]:
            match = parser.OFPMatch()
            match.set_dl_type(ether.ETH_TYPE_IP)
            match.set_ip_proto(inet.IPPROTO_TCP)
            match.set_ipv4_src_masked(rule.ip_src,rule.ip_src_mask)
            match.set_ipv4_dst_masked(rule.ip_dst,rule.ip_dst_mask)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            self.logger.debug( "install flow %d %d %d %d" % (rule.ip_src, rule.ip_src_mask, rule.ip_dst, rule.ip_dst_mask))
            self.add_flow(datapath,1,rules.index(rule) + 1,match,inst)
        #second, send a barrier to ensure all rules installation are done
        datapath.send_barrier();

        #thrid, install bucket
        bucket = rules[0]
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_TCP)
        match.set_ipv4_src_masked(bucket.ip_src,bucket.ip_src_mask)
        match.set_ipv4_dst_masked(bucket.ip_dst,bucket.ip_dst_mask)
        inst = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath,0,1,match,inst)
        self.logger.debug( "install bucket %d %d %d %d" % (bucket.ip_src, bucket.ip_src_mask, bucket.ip_dst, bucket.ip_dst_mask))
