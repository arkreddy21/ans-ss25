"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

from ryu.lib.packet import ethernet, ether_types
from ipaddress import IPv4Address, IPv4Network

import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.k = 4
        self.topo_net = topo.Fattree(4)
        # get out_port for a particular switch(dpid) and the destination IP that is directly connected
        self.dst_to_port = {} # format {(dpid, dst_ip): port}

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        # switches = get_switch(self, None)
        links = get_link(self, None)
        #TODO why is len(links) 64 and not 48
        print(f"no. of links: {len(links)}")

        for link in links:
            # if link.src.dpid == dp.id:
            switch_port = link.src.port_no
            neighbour_ip = IPv4Address(link.dst.dpid)
            self.dst_to_port[(link.src.dpid, neighbour_ip)] = switch_port
            # elif link.dst.dpid == dp.id:
            switch_port = link.dst.port_no
            neighbour_ip = IPv4Address(link.src.dpid)
            self.dst_to_port[(link.dst.dpid, neighbour_ip)] = switch_port
        # TODO only 63 entries are printing when it should be 80 entries
        # print(self.dst_to_port)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TODO: handle new packets at the controller
        switch_ip = IPv4Address(dpid)
        switch_node = self.topo_net.node_by_ip(switch_ip)
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)  # raw packet
        eth = pkt.get_protocol(ethernet.ethernet)  # ethernet packet

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = IPv4Address(ip_pkt.src)
            dst_ip = IPv4Address(ip_pkt.dst)
            print(f"IP4 packet {src_ip} -> {dst_ip}, switch {switch_ip}, port {in_port}")
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = IPv4Address(arp_pkt.src_ip)
            dst_ip = IPv4Address(arp_pkt.dst_ip)
            print(f"ARP packet {src_ip} -> {dst_ip}, switch {switch_ip}, port {in_port}")
        else: # ignore packets that are neither IP or ARP
            return
        

        # checking the switch and pod numbers in `10.pod.switch.id` pattern
        # Core switch
        if self.get_octet(switch_ip, 1) == self.k:
            # forward to correct port based on pod number (10.pod in dst_ip)
            # also add corresponding flow rule for it
            target_pod = self.get_octet(dst_ip, 1)
            out_port = None
            for (switch_dpid, ip), port in self.dst_to_port.items():
                if switch_dpid == dpid and self.get_octet(ip, 1) == target_pod:
                    out_port = port
            if out_port == None:
                print(f"Core switch {dpid} unable to find target out port")
                return

            match = parser.OFPMatch(ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
            self.send_packet_out(datapath, in_port, actions, msg.data)
        
        # Aggregation switch
        if self.get_octet(switch_ip, 1) < self.k and self.get_octet(switch_ip, 2) >= self.k//2 :
            switch_pod = self.get_octet(switch_ip, 1)
            target_pod = self.get_octet(dst_ip, 1)
            out_port = None
            # Same pod - forward to edge switch
            if switch_pod == target_pod:
                target_switch = self.get_octet(dst_ip, 2)
                for (switch_dpid, ip), port in self.dst_to_port.items():
                    if switch_dpid == dpid and self.get_octet(ip, 2) == target_switch:
                        out_port = port
                if out_port == None:
                    print(f"Aggr switch {dpid} unable to find target out port")
                    return
            else: # Different pod. Decide on k/2 core switches
                pass

            match = parser.OFPMatch(ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
            self.send_packet_out(datapath, in_port, actions, msg.data)
        
        # Edge switch
        if self.get_octet(switch_ip, 1) < self.k and self.get_octet(switch_ip, 2) < self.k//2:
            # destination is connected to same edge switch
            if (self.get_octet(dst_ip, 2) == self.get_octet(switch_ip, 2)):
                out_port = self.dst_to_port[(dpid, dst_ip)]
                match = parser.OFPMatch(ipv4_dst=dst_ip)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, in_port, actions, msg.data)
            # else forward packet to aggr switch
            else:
                pass


    # Extracts the value of the octet from the IP
    def get_octet(self, ip_address, octet_number):
        return int(str(ip_address).split('.')[octet_number])
    
    def send_packet_out(self, datapath, in_port, actions, data):
        """send packet out message via the given datapath"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        ))
