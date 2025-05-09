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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller

        # Datapath IDs to differentiate switches and routers
        self.switch_dpids = [1, 2]
        self.router_dpids = [3]

        # Switches MAC address table
        self.switch_mac_to_port = {}

        # ARP table for router (IP -> MAC)
        self.router_arp_table = {}

        # Router port MACs assumed by the controller
        ## TODO discover virtual mac addresses
        self.router_port_to_own_mac = {
            1: '00:00:00:00:01:01',
            2: '00:00:00:00:01:02',
            3: '00:00:00:00:01:03'
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.router_port_to_own_ip = {
            1: '10.0.1.1',
            2: '10.0.2.1',
            3: '192.168.1.1'
        }

        # Router (subnet -> router port)
        self.router_subnets = {
            '10.0.1.0/24': 1,
            '10.0.2.0/24': 2,
            '192.168.1.0/24': 3
        }
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
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

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

        # Your controller implementation should start here

        # Differentiate b/w switches and router based on datapath
        if datapath.id in self.switch_dpids:
            self.logger.info("switch packet dpid: %s", datapath.id)
            self.switch_packet_handler(ev)
        elif datapath.id in self.router_dpids:
            self.logger.info("router packet dpid: %s", datapath.id)
            self.router_packet_handler(ev)
        else:
            self.logger.warning("Unknown datapath: %s", dpid)
    
    
    def switch_packet_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # raw packet data
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets
            return
            
        # Get destination and source MAC addresses
        dst_mac = eth.dst
        src_mac = eth.src

        # Learn MAC address to avoid FLOOD next time
        self.switch_mac_to_port.setdefault(dpid, {})
        self.switch_mac_to_port[dpid][src_mac] = in_port

        # Determine output port
        if dst_mac in self.switch_mac_to_port[dpid]:
            out_port = self.switch_mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            # Verify if we have a valid buffer_id
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Send packet out for all cases
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def router_packet_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Handle different packet types
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets
            return
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip_packet(msg, pkt, eth, datapath, in_port, parser, ofproto)
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp_packet(msg, pkt, eth, datapath, in_port, parser, ofproto)
    
    
    def handle_ip_packet(self, msg, pkt, eth, datapath, in_port, parser, ofproto):
        """Handle IP packets for routing with security policies"""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return
            
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto
        
        self.logger.info("Router: IP packet %s -> %s (proto: %s)", src_ip, dst_ip, protocol)
        
        # TODO Check security policies
            
        # Route the packet
        out_port = self.get_out_port_for_ip(dst_ip)
        if out_port is None:
            self.logger.info("No route found for %s", dst_ip)
            return

        # If the destination is on a different subnet, update the MAC
        if self.different_subnet(ip_pkt.src, ip_pkt.dst):
            # Get destination MAC based on routing
            if dst_ip in self.router_arp_table:
                dst_mac = self.router_arp_table[dst_ip]
            else:
                # If MAC not known yet, you might trigger ARP (not implemented)
                self.logger.info("MAC not found for %s, dropping packet", dst_ip)
                return
                
            # Set source MAC as the router's MAC for the outgoing interface
            #TODO get router ports mac addresses
            src_mac = self.router_port_to_own_mac[out_port]
            
            # Update packet headers for forwarding
            actions = [
                parser.OFPActionSetField(eth_src=src_mac),
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port)
            ]
            
            # Install a flow for future packets
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=dst_ip
            )
            self.add_flow(datapath, 1, match, actions)
            
            # Send the current packet
            self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)
        else:
            # Same subnet, just forward (this shouldn't normally happen for a router)
            actions = [parser.OFPActionOutput(out_port)]
            self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)

    def handle_arp_packet(self, msg, pkt, eth, datapath, in_port, parser, ofproto):
        """Handle ARP packets"""
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return
            
        # Log ARP packet
        self.logger.info("Router: ARP packet %s (%s) -> %s", arp_pkt.src_ip, arp_pkt.src_mac, arp_pkt.dst_ip)
        
        # Update ARP table with the source
        self.router_arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        # Handle ARP request
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if request is for one of the router's interfaces
            if arp_pkt.dst_ip in self.router_port_to_own_ip.values():
                # Find the port this IP belongs to
                port = None
                for p, ip in self.router_port_to_own_ip.items():
                    if ip == arp_pkt.dst_ip:
                        port = p
                        break
                
                if port is not None:
                    # Create ARP reply
                    router_mac = self.router_port_to_own_mac[port]
                    self.logger.info("sending ARP reply for router gateway")
                    self.send_arp_reply(datapath, eth, arp_pkt, router_mac, in_port)
                    return
            # If not for router, check if we know the destination
            elif arp_pkt.dst_ip in self.router_arp_table:
                # Route the ARP request
                out_port = self.get_out_port_for_ip(arp_pkt.dst_ip)
                if out_port and out_port != in_port:
                    actions = [parser.OFPActionOutput(out_port)]
                    self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)
            else:
                # Flood ARP request if we don't know the destination
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)
        # Handle ARP reply
        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Update ARP table
            self.router_arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
            
            # Check if the reply is for a known destination
            if arp_pkt.dst_ip in self.router_port_to_own_ip.values():
                # Reply is for the router, no need to forward
                return
            else:
                # Forward the ARP reply to the appropriate port
                out_port = self.get_out_port_for_ip(arp_pkt.dst_ip)
                if out_port:
                    actions = [parser.OFPActionOutput(out_port)]
                    self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)
    
    def send_arp_reply(self, datapath, eth_pkt, arp_pkt, router_mac, in_port):
        """Create and send an ARP reply"""
        parser = datapath.ofproto_parser
        
        # Create Ethernet packet
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_pkt.src,
            src=router_mac))
            
        # Create ARP reply packet
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=router_mac,
            src_ip=arp_pkt.dst_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip))
            
        # Serialize and send
        pkt.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        self.send_packet(datapath, None, datapath.ofproto.OFPP_CONTROLLER, 
                       actions, pkt.data, datapath.ofproto)
  
    def send_packet(self, datapath, buffer_id, in_port, actions, data, ofproto):
        """Send packet out message to the datapath"""
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        out = parser.OFPPacketOut(datapath=datapath,
                                 buffer_id=buffer_id,
                                 in_port=in_port,
                                 actions=actions,
                                 data=data)
        datapath.send_msg(out)

    def get_out_port_for_ip(self, ip):
        """Determine outgoing port in the router based on destination IP"""
        # Find which subnet the IP belongs to
        for subnet, port in self.router_subnets.items():
            network, mask = subnet.split('/')
            mask_bits = int(mask)
            
            # Simple subnet check using string operations
            ip_parts = ip.split('.')
            net_parts = network.split('.')
            
            # Convert to binary and check if the first mask_bits match
            ip_binary = ''.join([bin(int(p))[2:].zfill(8) for p in ip_parts])
            net_binary = ''.join([bin(int(p))[2:].zfill(8) for p in net_parts])
            
            if ip_binary[:mask_bits] == net_binary[:mask_bits]:
                return port
                
        return None
    
    def different_subnet(self, ip1, ip2):
        """Check if two IPs are in different subnets"""
        port1 = self.get_out_port_for_ip(ip1)
        port2 = self.get_out_port_for_ip(ip2)
        return port1 != port2 if port1 and port2 else True
