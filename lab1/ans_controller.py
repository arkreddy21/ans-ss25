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
from ryu.lib.packet import arp, ipv4, icmp
from ipaddress import IPv4Address, IPv4Network


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
        # Router ARP table (IP -> MAC)
        self.router_arp_table = {}
        # Router port MACs assumed by the controller
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
        # Router: buffer IP packet if dst MAC is not known
        self.pending_packets = {} # format: {dst_ip: [msg]}

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
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Differentiate b/w switches and router based on datapath
        if dpid in self.switch_dpids:
            self.switch_packet_handler(msg, datapath, ofproto, parser)
        elif dpid in self.router_dpids:
            self.router_packet_handler(msg, datapath, ofproto, parser)
        else:
            self.logger.warning("Unknown datapath: %s", dpid)

    
    def switch_packet_handler(self, msg, datapath, ofproto, parser):
        dpid = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)  # raw packet
        eth = pkt.get_protocol(ethernet.ethernet)  # ethernet packet
        
        # map the source MAC address to input port
        self.switch_mac_to_port.setdefault(dpid, {}) # separate map for each switch based on dpid
        self.switch_mac_to_port[dpid][eth.src] = in_port

        # Determine output port
        if eth.dst in self.switch_mac_to_port[dpid]:
            out_port = self.switch_mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install the corresponding flow rule
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)

        self.send_packet_out(datapath, in_port, actions, msg.data)

    def router_packet_handler(self, msg, datapath, ofproto, parser):
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)  # raw packet
        eth = pkt.get_protocol(ethernet.ethernet)  # ethernet packet
        
        # Handle different packet types
        # Refer https://github.com/faucetsdn/ryu/blob/master/ryu/lib/packet/ether_types.py
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.router_ip_handler(msg, pkt, eth, datapath, in_port, ofproto, parser)
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.router_arp_handler(pkt, eth, datapath, in_port, ofproto, parser)

    def router_ip_handler(self, msg, pkt, eth, datapath, in_port, ofproto, parser):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto
        self.logger.info("Router: IP packet %s -> %s (protocol: %s)", src_ip, dst_ip, protocol)

        # update ARP table with source IP -> source MAC
        self.router_arp_table[src_ip] = eth.src
        
        # handle ICMP pings to router's gateway
        if protocol == 1 and dst_ip in self.router_port_to_own_ip.values():
            # block pings from a host to other gateways
            if dst_ip != self.router_port_to_own_ip[in_port]:
                self.logger.warning("Router: Security - Host %s not allowed to ping gateway %s", src_ip, dst_ip)
                self.router_icmp_handler(datapath, msg, ofproto, parser, in_port, eth.src, ip_pkt.src, None, 3, 1)
                return
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == 8: # ICMP ping echo request
                self.router_icmp_handler(datapath, msg, ofproto, parser, in_port, eth.src, ip_pkt.src, icmp_pkt)
                return
        # handle security conditions
        if not self.security_check(msg, ip_pkt, eth, datapath, in_port, ofproto, parser):
            return

        # Get out port based on known router subnets
        out_port = None
        for port, gateway in self.router_port_to_own_ip.items():
            if IPv4Address(dst_ip) in IPv4Network(f"{gateway}/24", strict=False):
                out_port = port
                break
        if out_port == None:
            self.logger.warning("Router: no route found %s", dst_ip)
            self.router_icmp_handler(datapath, msg, ofproto, parser, in_port, eth.src, ip_pkt.src, None, 3, 1)
            return
        
        src_mac = self.router_port_to_own_mac[out_port]
        # If destination MAC is not known, send an ARP request
        if dst_ip not in self.router_arp_table:
            self.logger.info("Router: Unknown MAC for %s, sending ARP request", dst_ip)
            if dst_ip not in self.pending_packets:
                self.pending_packets[dst_ip] = []
            self.pending_packets[dst_ip].append(msg)
            # Send ARP request
            self.send_arp_request(datapath, out_port, self.router_port_to_own_mac[out_port], 
                                 self.router_port_to_own_ip[out_port], dst_ip, ofproto, parser)
            return
        dst_mac = self.router_arp_table[dst_ip]

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        # Decrement TTL, modify src and dst MAC, set output port. Order matters
        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        self.add_flow(datapath, 1, match, actions)
        self.send_packet_out(datapath, in_port, actions, msg.data)

    def router_arp_handler(self, pkt, eth, datapath, in_port, ofproto, parser):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return

        self.logger.info("Router: ARP packet %s [%s] -> %s", arp_pkt.src_ip, arp_pkt.src_mac, arp_pkt.dst_ip)
        # Update ARP table with the source IP and MAC
        self.router_arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        # Respond to ARP request directed at router
        if (arp_pkt.opcode == arp.ARP_REQUEST) and arp_pkt.dst_ip == self.router_port_to_own_ip[in_port]:
            arp_response_pkt = packet.Packet()
            arp_response_pkt.add_protocol(ethernet.ethernet(
                dst=eth.src,
                src=self.router_port_to_own_mac[in_port],
                ethertype=ether_types.ETH_TYPE_ARP
            ))
            arp_response_pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.router_port_to_own_mac[in_port],
                src_ip=arp_pkt.dst_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip
            ))
            actions=[parser.OFPActionOutput(in_port)]
            arp_response_pkt.serialize()
            self.send_packet_out(datapath, ofproto.OFPP_CONTROLLER, actions, arp_response_pkt.data)
        
        if (arp_pkt.opcode == arp.ARP_REPLY):
            src_ip = arp_pkt.src_ip
            # Update ARP table
            self.router_arp_table[src_ip] = arp_pkt.src_mac
            # Process pending packets now that we have MAC
            if src_ip in self.pending_packets:
                self.logger.info("Router: Processing %d pending packets for %s", 
                                len(self.pending_packets[src_ip]), src_ip)
                for msg in self.pending_packets[src_ip]:
                    self.router_ip_handler(msg, packet.Packet(msg.data), 
                                         packet.Packet(msg.data).get_protocol(ethernet.ethernet),
                                         msg.datapath, msg.match['in_port'], ofproto, parser)
                # Clear processed packets
                del self.pending_packets[src_ip]
    
    def send_arp_request(self, datapath, port, src_mac, src_ip, dst_ip, ofproto, parser):
        """Send an ARP request packet for an unknown destination IP"""
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',  # Broadcast
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        ))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',  # Unknown target MAC
            dst_ip=dst_ip
        ))
        p.serialize()
        actions = [parser.OFPActionOutput(port)]
        self.send_packet_out(datapath, ofproto.OFPP_CONTROLLER, actions, p.data)

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
    
    def router_icmp_handler(self, datapath, msg, ofproto, parser, in_port, src_mac, src_ip, icmp_pkt=None, icmp_type=0, icmp_code=0):
        """
        General function to send ICMP messages from the router. \n
        ICMP types and codes handled: \n
        (0,  0): echo reply \n
        (3,  1): destination host unreachable \n
        Refer https://github.com/faucetsdn/ryu/blob/master/ryu/lib/packet/icmp.py#L26
        """
        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(ethernet.ethernet(
            dst=src_mac,
            src=self.router_port_to_own_mac[in_port],
            ethertype=ether_types.ETH_TYPE_IP
        ))
        reply_pkt.add_protocol(ipv4.ipv4(
            dst=src_ip,
            src=self.router_port_to_own_ip[in_port],
            proto=1, #ICMP protocol
            ttl=64
        ))

        # ICMP data - content depend on the type
        icmp_data = None
        # Echo reply for ping. Preserve original data
        # Refer https://github.com/faucetsdn/ryu/blob/master/ryu/lib/packet/icmp.py#L137
        if icmp_type == 0 and isinstance(icmp_pkt.data, icmp.echo):
            icmp_data = icmp.echo(
                id_=icmp_pkt.data.id,
                seq=icmp_pkt.data.seq,
                data=icmp_pkt.data.data
            )
        elif icmp_type == 3: # destination unreachable
            # Include original IP header + 8 bytes of data as per RFC
            ip_pkt_bin = bytearray(msg.data[14:])  # Skip Ethernet header (14 bytes)
            data_len = min(len(ip_pkt_bin), 28)  # 20 bytes IP header + 8 bytes data
            icmp_data = icmp.dest_unreach(data=bytes(ip_pkt_bin[:data_len]))

        reply_pkt.add_protocol(icmp.icmp(
            type_=icmp_type,
            code=icmp_code,
            csum=0,
            data=icmp_data
        ))

        reply_pkt.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        self.logger.info("Router: Sending ICMP type %d, code %d to host %s", icmp_type, icmp_code, src_ip)
        self.send_packet_out(datapath, ofproto.OFPP_CONTROLLER, actions, reply_pkt.data)        

    def security_check(self, msg, ip_pkt, eth, datapath, in_port, ofproto, parser):
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        proto = ip_pkt.proto
        # 1: Block ICMP from/to external host
        if proto == 1 and (src_ip == self.external_ip or dst_ip == self.external_ip):  # ICMP
            self.logger.warning("Security: Blocked ICMP from external host %s", src_ip)
            self.router_icmp_handler(datapath, msg, ofproto, parser, in_port, eth.src, src_ip, None, 3, 1)
            return False
         # 2: Block TCP/UDP between external host and server
        if (proto in [6, 17]) and ((src_ip == self.external_ip and dst_ip == self.server_ip) or \
               (src_ip == self.server_ip and dst_ip == self.external_ip)):
            self.logger.warning("Security: Blocked protocol %s between %s and %s", proto, src_ip, dst_ip)
            return False
        return True
