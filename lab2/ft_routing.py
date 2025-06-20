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
from ipaddress import IPv4Address

import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.k = 4
        self.topo_net = topo.Fattree(4)
        # get out_port for a particular switch(dpid) and the destination IP that is directly connected
        self.dst_to_port = {} # format {dpid: {dst_ip: port}}

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        dpid = ev.switch.dp.id
        links = get_link(self, dpid)
        for link in links:
            # from switch 1 to switch 2
            switch_port = link.src.port_no
            neighbour_ip = IPv4Address(link.dst.dpid)
            self.dst_to_port.setdefault(link.src.dpid, {})
            self.dst_to_port[link.src.dpid][neighbour_ip] = switch_port
            # from switch 2 to switch 1
            switch_port = link.dst.port_no
            neighbour_ip = IPv4Address(link.src.dpid)
            self.dst_to_port.setdefault(link.dst.dpid, {})
            self.dst_to_port[link.dst.dpid][neighbour_ip] = switch_port
        print(f"no. of switches discovered: {len(self.dst_to_port)}")


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

        switch_ip = IPv4Address(dpid)
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)  # raw packet
        eth = pkt.get_protocol(ethernet.ethernet)  # ethernet packet

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = IPv4Address(ip_pkt.src)
            dst_ip = IPv4Address(ip_pkt.dst)
            print(f"IP4 packet {src_ip} -> {dst_ip}, switch {switch_ip}")
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = IPv4Address(arp_pkt.src_ip)
            dst_ip = IPv4Address(arp_pkt.dst_ip)
            print(f"ARP packet {src_ip} -> {dst_ip}, switch {switch_ip}")
        else: # ignore packets that are neither IP or ARP
            return
        
        # learn Host's port to switch
        self.dst_to_port[dpid][src_ip] = in_port

        # check the switch and pod numbers in `10.pod.switch.id` pattern
        # Core switch
        if self.get_octet(switch_ip, 1) == self.k:
            self.populate_core_flows(datapath)
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
            self.send_packet_out(datapath, in_port, actions, msg.data)
        
        # Aggregation switch
        elif self.get_octet(switch_ip, 2) >= self.k//2 :
            self.populate_aggr_flows(datapath)      
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]         
            self.send_packet_out(datapath, in_port, actions, msg.data)
        
        # Edge switch
        else:
            # destination is connected to same edge switch
            if self.get_octet(dst_ip, 1) == self.get_octet(switch_ip, 1) and self.get_octet(dst_ip, 2) == self.get_octet(switch_ip, 2):
                # Get all possible out ports if we don't know the exact port the host is connected to
                if dst_ip in self.dst_to_port[dpid]:
                    out_ports = [self.dst_to_port[dpid][dst_ip]]
                else:
                    out_ports = list(({1,2,3,4} - set(self.dst_to_port[dpid].values())))
                actions = [parser.OFPActionOutput(port) for port in out_ports]
                if len(out_ports) == 1:
                    match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=str(dst_ip))
                    match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=str(dst_ip))
                    self.add_flow(datapath, 2, match_ip, actions)
                    self.add_flow(datapath, 2, match_arp, actions)
            # else forward packet to aggr switch. Distribude based on switch octet
            else:
                out_port = None
                for ip, port in self.dst_to_port[dpid].items():
                    if self.get_octet(ip, 2) != self.get_octet(switch_ip, 2) and self.get_octet(ip, 2) - self.k//2 == self.get_octet(dst_ip, 2):
                        out_port = port
                        break
                if out_port is None:
                    print(f"Edge switch {dpid} unable to find target out port")
                    return
                actions = [parser.OFPActionOutput(out_port)]
                match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=f"{str(dst_ip)}/24")
                match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=f"{str(dst_ip)}/24")
                self.add_flow(datapath, 1, match_ip, actions)
                self.add_flow(datapath, 1, match_arp, actions)

            self.send_packet_out(datapath, in_port, actions, msg.data)
   
    def populate_core_flows(self,datapath):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ip = IPv4Address(dpid)
        switch = self.get_octet(ip,2)
        for i in range(self.k):
            port = self.dst_to_port[dpid][IPv4Address(f"10.{i}.{self.k//2 + switch - 1}.1")]
            match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=f"10.{i}.0.0/16")
            match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=f"10.{i}.0.0/16")
            actions = [parser.OFPActionOutput(port)]
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    def populate_aggr_flows(self, datapath):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ip = IPv4Address(dpid)
        pod = self.get_octet(ip,1)
        switch = self.get_octet(ip,2)
        # add flow rules for ports to edge switches in same pod
        for i in range(self.k//2):
            port = self.dst_to_port[dpid][IPv4Address(f"10.{pod}.{i}.1")]
            match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=f"10.{pod}.{i}.0/24")
            match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=f"10.{pod}.{i}.0/24")
            actions = [parser.OFPActionOutput(port)]
            self.add_flow(datapath, 2, match_ip, actions)
            self.add_flow(datapath, 2, match_arp, actions)
        # add flow rules for ports to core switches. Distribute based on /8 suffix
        for i in range(2, (self.k//2)+2):
            port = self.dst_to_port[dpid][IPv4Address(f"10.4.{switch-(self.k//2)+1}.{i-1}")]
            match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(f"0.0.0.{i}","0.0.0.255"))
            match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=(f"0.0.0.{i}","0.0.0.255"))
            actions = [parser.OFPActionOutput(port)]
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    def get_octet(self, ip_address, octet_number):
        """Extracts the value of the octet from the IP"""
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
