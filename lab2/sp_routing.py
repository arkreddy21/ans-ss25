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
from itertools import chain

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
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
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
    
        switch_node = self.topo_net.node_by_ip(switch_ip)
        dst_node = self.topo_net.node_by_ip(dst_ip)
    
        # Get shortest paths from current switch to all destinations
        paths = self.single_source_shortest_paths(switch_node, dst_node)
    
        if dst_node not in paths:
            print(f"No path found from {switch_ip} to {dst_ip}")
            return
    
        path = paths[dst_node]
        print(f"Path from {switch_ip} to {dst_ip}: {[str(node.ip) for node in path]}")
    
        # Case 1: Destination is directly connected to current switch
        if len(path) == 2:  # [current_switch, destination_host]
            out_ports = self.get_port_for_ip(dpid, dst_ip)
            print(f"Direct connection - out_ports: {out_ports}")
    
            # Send packet out
            actions = [parser.OFPActionOutput(out_port) for out_port in out_ports]
            self.send_packet_out(datapath, ofproto.OFPP_CONTROLLER, actions, msg.data)
    
            # Install flow rule if we know the exact port
            if len(out_ports) == 1:
                match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=str(dst_ip))
                match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=str(dst_ip))
                self.add_flow(datapath, 1, match_ip, actions)
                self.add_flow(datapath, 1, match_arp, actions)
    
        # Case 2: Multi-hop path - forward to next switch
        else:
            next_hop = path[1]  # Next switch in the path
            next_hop_ip = IPv4Address(int(next_hop.ip))
    
            # Get port to next hop switch
            if next_hop_ip in self.dst_to_port[dpid]:
                out_port = self.dst_to_port[dpid][next_hop_ip]
                print(f"Forwarding to next hop switch {next_hop_ip} via port {out_port}")
    
                # Send packet to next hop
                actions = [parser.OFPActionOutput(out_port)]
                match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=str(dst_ip))
                match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=str(dst_ip))
                self.add_flow(datapath, 1, match_ip, actions)
                self.add_flow(datapath, 1, match_arp, actions)
                self.send_packet_out(datapath, ofproto.OFPP_CONTROLLER, actions, msg.data)
            else:
                print(f"No port found for next hop {next_hop_ip}")


    def single_source_shortest_paths(self, source, sink=None):
        """
        Run breadth-first search to find the shortest paths to all (other) servers.
        """
        shortest_paths = {source: [source]}
        queue= [source]

        for node in chain(self.topo_net.servers, self.topo_net.switches):
            node.visited = False

        while len(queue) != 0:
            current_node = queue.pop(0)
            current_path = shortest_paths[current_node]

            for edge in current_node.edges:
                neighbor = edge.lnode if edge.lnode is not current_node else edge.rnode

                if not neighbor.visited:
                    shortest_paths[neighbor] = current_path + [neighbor]
                    if neighbor is sink:
                        return shortest_paths
                    neighbor.visited = True
                    queue.append(neighbor)

        return shortest_paths
    
    def get_port_for_ip(self, dpid, ip):
        """Get a list of ports to forward a packet to; for a given switch and destination IP"""
        if ip in self.dst_to_port[dpid]:
            return [self.dst_to_port[dpid][ip]]
        else:
            ports = list(({1,2,3,4} - set(self.dst_to_port[dpid].values())))
            return ports

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
