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

import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

from topo import Fattree


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)

        # TODO: please complete the network generation logic here
        linkopts = dict(bw=15, delay='5ms')
        for switch in ft_topo.switches:
            self.addSwitch(switch.id, dpid=hex(int(switch.ip))[2:])
            # add links only for aggregation switches. It's enough to cover the whole network
            if not switch.type.startswith("aggr"):
                continue
            for edge in switch.edges:
                self.addLink(edge.lnode.id, edge.rnode.id, **linkopts) 
        for server in ft_topo.servers:
            self.addHost(server.id, ip=str(server.ip))
            # link server to edge switch
            for edge in server.edges:
                self.addLink(edge.lnode.id, edge.rnode.id, **linkopts)


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True, switch=OVSKernelSwitch, link=TCLink)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)

    pairs = [("h0", "h8"), ("h2", "h10"), ("h4", "h12"), ("h6", "h14")]
    pairs = [(net.get(a_node), net.get(b_node)) for (a_node, b_node) in pairs]
    info('*** Running Benchmark ***\n')
    with ThreadPoolExecutor(max_workers=len(graph_topo.switches)) as executor:
        executor.map(lambda pair: net.iperf(hosts=pair, seconds=10), pairs)

    info('*** Stopping network ***\n')
    net.stop()


if __name__ == '__main__':
    # ft_topo = topo.Fattree(4)
    ft_topo = Fattree(4)
    run(ft_topo)
