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
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import arp, ipv4, icmp, tcp, udp


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

        # Buffer for packets waiting for ARP replies
        self.pending_packets = {}  # Format: {dst_ip: [(msg, pkt, in_port), ...]}

        self.external_ip = '192.168.1.123'  # External host
        self.server_ip = '10.0.2.2'        # Internal server
        

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

        # Only install security policies on the router
        if datapath.id in self.router_dpids:
            self.install_security_policies(datapath)

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
            self.switch_packet_handler(ev)
        elif datapath.id in self.router_dpids:
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

        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     # Ignore LLDP packets
        #     return
        
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
        # Refer https://github.com/faucetsdn/ryu/blob/master/ryu/lib/packet/ether_types.py
        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     # Ignore LLDP packets
        #     return
        if eth.ethertype == ether_types.ETH_TYPE_IP:
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

        # Check if packet is ICMP ping to router (gateway)
        if (dst_ip in self.router_port_to_own_ip.values()) and (protocol == 1):
            self.handle_icmp_to_router(msg, pkt, eth, ip_pkt, datapath, in_port, parser, ofproto)
            return
        
        # Route the packet

        # Check if the dst ip address belongs to one of the subnets or not
        out_port = self.get_out_port_for_ip(dst_ip)
        if out_port is None:
            self.logger.info("No route found for %s", dst_ip)
            return

        # If the destination is on a different subnet, update the MAC
        if self.different_subnet(ip_pkt.src, ip_pkt.dst):
            # Get destination MAC based on routing
            if dst_ip in self.router_arp_table:
                dst_mac = self.router_arp_table[dst_ip]
                # Set source MAC as the router's MAC for the outgoing interface
                src_mac = self.router_port_to_own_mac[out_port]

                # Install a flow for future packets
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=dst_ip
                )

                # Update packet headers for forwarding
                actions = [
                    parser.OFPActionSetField(eth_src=src_mac),
                    parser.OFPActionSetField(eth_dst=dst_mac),
                    parser.OFPActionOutput(out_port)
                ]

                self.add_flow(datapath, 1, match, actions)

                # Send the current packet
                self.send_packet(datapath, msg.buffer_id, in_port, actions, msg.data, ofproto)
            else:
                # MAC is not known yet, trigger ARP request
                # Store the packet for later processing
                if dst_ip not in self.pending_packets:
                    self.pending_packets[dst_ip] = []

                # Buffer the packet
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    self.pending_packets[dst_ip].append((msg, pkt, in_port))
                else:
                    # Need to fetch packet data if we have a buffer_id
                    self.pending_packets[dst_ip].append((msg, pkt, in_port))

                # Get router's IP for the outgoing port
                src_ip = self.router_port_to_own_ip[out_port]
                src_mac = self.router_port_to_own_mac[out_port]

                # Send ARP request to discover destination MAC
                self.send_arp_request(datapath, src_mac, src_ip, dst_ip, out_port)

                self.logger.info("Sent ARP request for %s and buffered packet", dst_ip)
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

        # Check if we have pending packets for this IP
        if arp_pkt.src_ip in self.pending_packets:
            self.logger.info("Processing buffered packets for %s", arp_pkt.src_ip)
            dst_ip = arp_pkt.src_ip
            dst_mac = arp_pkt.src_mac

            # Process all pending packets
            for buffered_msg, buffered_pkt, buffered_in_port in self.pending_packets[dst_ip]:
                # Find the outgoing port for the IP
                out_port = self.get_out_port_for_ip(dst_ip)
                if out_port:
                    # Get router's MAC for the outgoing port
                    src_mac = self.router_port_to_own_mac[out_port]

                    # Create actions for the packet
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

                    # Send the packet
                    self.send_packet(datapath, buffered_msg.buffer_id, 
                                    buffered_in_port, actions, buffered_msg.data, ofproto)

            # Clear the pending packets for this IP
            del self.pending_packets[dst_ip]

        # Handle ARP request
        # opcode refernece - https://github.com/faucetsdn/ryu/blob/master/ryu/lib/packet/arp.py
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

    def send_arp_request(self, datapath, src_mac, src_ip, dst_ip, out_port):
        """Send an ARP request to discover MAC address for destination IP"""
        self.logger.info("Sending ARP request for %s from port %s", dst_ip, out_port)

        # Create ARP request packet
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst='ff:ff:ff:ff:ff:ff',  # Broadcast
            src=src_mac))

        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',  # Unknown
            dst_ip=dst_ip))

        # Serialize and send
        pkt.serialize()
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
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

    def handle_icmp_to_router(self, msg, pkt, eth, ip_pkt, datapath, in_port, parser, ofproto):
        """Handle ICMP packets destined for the router itself"""
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if icmp_pkt is None:
            return

        # Only respond to ICMP Echo Requests (Type 8)
        if icmp_pkt.type != 8:
            return

        self.logger.info("Received ICMP Echo Request for router IP %s", ip_pkt.dst)

        # Find which router interface was pinged
        port = None
        for p, ip in self.router_port_to_own_ip.items():
            if ip == ip_pkt.dst:
                port = p
                break
            
        if port is None:
            return

        # Get router MAC for the interface
        src_mac = self.router_port_to_own_mac[port]
        dst_mac = eth.src

        # Create Echo Reply packet
        echo_reply_pkt = packet.Packet()

        # Add Ethernet header
        echo_reply_pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_IP,
            dst=dst_mac,
            src=src_mac))

        # Add IP header
        echo_reply_pkt.add_protocol(ipv4.ipv4(
            proto=1,  # ICMP
            src=ip_pkt.dst,  # Router's IP
            dst=ip_pkt.src,  # Host's IP
            ttl=64))

        # Add ICMP header - Echo Reply (Type 0)
        echo_reply_pkt.add_protocol(icmp.icmp(
            type_=0,  # Echo Reply
            code=0,
            csum=0,
            data=icmp_pkt.data))

        # Serialize the packet
        echo_reply_pkt.serialize()

        # Send the packet out
        actions = [parser.OFPActionOutput(in_port)]
        self.send_packet(datapath, None, ofproto.OFPP_CONTROLLER, 
                       actions, echo_reply_pkt.data, ofproto)

        self.logger.info("Sent ICMP Echo Reply to %s", ip_pkt.src)

    def install_security_policies(self, datapath):
        """Install security policy rules proactively with high priority"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Policy 1: External host cannot ping any other hosts
        # Block ICMP from external host
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.external_ip,
            ip_proto=1  # ICMP
        )
        self.add_flow(datapath, 100, match, [])  # Empty action list = drop

        # Policy 2: Hosts can only ping their own gateway
        # We need to block pings to non-own gateways for each subnet
        for src_subnet, src_port in self.router_subnets.items():
            src_gateway = self.router_port_to_own_ip[src_port]

            # For each gateway that is not the host's own gateway
            for dst_port, dst_gateway in self.router_port_to_own_ip.items():
                if dst_port != src_port:
                    # Block ICMP to this gateway from this subnet
                    network, mask = src_subnet.split('/')
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=(network, self._make_netmask(int(mask))),
                        ipv4_dst=dst_gateway,
                        ip_proto=1  # ICMP
                    )
                    self.add_flow(datapath, 100, match, [])

        # Policy 3: No TCP/UDP connections between external and internal server
        # Block TCP from external host to server
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.external_ip,
            ipv4_dst=self.server_ip,
            ip_proto=6  # TCP
        )
        self.add_flow(datapath, 100, match, [])

        # Block TCP from server to external host
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.server_ip,
            ipv4_dst=self.external_ip,
            ip_proto=6  # TCP
        )
        self.add_flow(datapath, 100, match, [])

        # Block UDP from external host to server
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.external_ip,
            ipv4_dst=self.server_ip,
            ip_proto=17  # UDP
        )
        self.add_flow(datapath, 100, match, [])

        # Block UDP from server to external host
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.server_ip,
            ipv4_dst=self.external_ip,
            ip_proto=17  # UDP
        )
        self.add_flow(datapath, 100, match, [])

    def _make_netmask(self, prefixlen):
        """Create an IPv4 netmask from prefix length"""
        return (0xffffffff << (32 - prefixlen)) & 0xffffffff
