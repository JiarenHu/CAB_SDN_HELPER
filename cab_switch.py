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


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        print 'OFPSwitchFeatures receive: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities)
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
        mod = parser.OFPFlowMod(datapath=datapath, table_id = table_id, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        in_port = msg.match['in_port']

        #datapath is the object which denotes the link between switch and controller
        datapath = msg.datapath
        dpid = datapath.id
        
        #ofproto and parser is version related
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        

        #msg.data is raw data.
        pkt = packet.Packet(msg.data)
        #header class: http://ryu.readthedocs.org/en/latest/library_packet_ref.html
        #get ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        self.logger.info("packet in %s:%s table %s %s %s ", 
                dpid, in_port,ev.msg.table_id ,src, dst )


        #try to pars ip header
        ip_header = pkt.get_protocol(ipv4.ipv4)
        
        #ip packet
        if ip_header != None:
            self.logger.info('ip src %s dst %s', ip_header.src, ip_header.dst)
        #non-ip packet do learning switch
        else:
            #learning switch part
            self.mac_to_port.setdefault(dpid, {})
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

            #install a flow to avoid packet_in next time
            #if out_port != ofproto.OFPP_FLOOD:
            #    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            #    self.add_flow(datapath, 1,1, match, inst)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        #try to pars tcp header
        tcp_header = pkt.get_protocol(tcp.tcp)
        if tcp_header != None:
            self.logger.info('tcp src %s dst %s', tcp_header.src_port, tcp_header.dst_port)
            request = pkt_h(ipv4_to_int(ip_header.src),ipv4_to_int(ip_header.dst), tcp_header.src_port, tcp_header.dst_port)
            rules = query(request)
            #first install rule
            for rule in rules[1:]:
                match = parser.OFPMatch()
                match.set_dl_type(ether.ETH_TYPE_IP)
                match.set_ip_proto(inet.IPPROTO_TCP)
                match.set_ipv4_src_masked(rule.ip_src,rule.ip_src_mask)
                match.set_ipv4_dst_masked(rule.ip_dst,rule.ip_dst_mask)
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD, ofproto.OFPCML_NO_BUFFER)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                print "install flow %d %d %d %d" % (rule.ip_src, rule.ip_src_mask, rule.ip_dst, rule.ip_dst_mask)
                self.add_flow(datapath,1,rules.index(rule) + 1,match,inst)
            bucket = rules[0]
            match = parser.OFPMatch()
            match.set_dl_type(ether.ETH_TYPE_IP)
            match.set_ip_proto(inet.IPPROTO_TCP)
            match.set_ipv4_src_masked(bucket.ip_src,bucket.ip_src_mask)
            match.set_ipv4_dst_masked(bucket.ip_dst,bucket.ip_dst_mask)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(datapath,0,1,match,inst)
            print "install bucket %d %d %d %d" % (bucket.ip_src, bucket.ip_src_mask, bucket.ip_dst, bucket.ip_dst_mask)
