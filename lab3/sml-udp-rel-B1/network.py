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

from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os

NUM_WORKERS = 8

class SMLTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # Make sure worker names are consistent with RunWorkers() below
        self.switch = self.addSwitch("s1")
        self.workers = [
            self.addHost(f"w{i}", ip=f"10.0.0.{i+1}", mac=f"08:00:00:00:00:{i+1:02x}")
            for i in range(NUM_WORKERS)
        ]
        for worker in self.workers:
            self.addLink(self.switch, worker)

def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    Redirects output to logs/<worker_name>.log (see lib/worker.py, Log())
    This function assumes worker i is named 'w<i>'. Feel free to modify it
    if your naming scheme is different
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    
    for i in range(NUM_WORKERS):
        worker_node = net.get(worker(i))
        cmd = ['python', 'worker.py', str(i)]
        with open(log_file(i), 'w') as logf:
            worker_node.popen(cmd, stdout=logf, stderr=logf)
    print("Workers started in background")

def RunControlPlane(net):
    """
    One-time control plane configuration
    """
    switch = net.get("s1")

    # Ethernet forwarding rules
    for i in range(NUM_WORKERS):
        switch.insertTableEntry(
            table_name="TheIngress.eth_exact",
            match_fields={"hdr.eth.dst": f"08:00:00:00:00:{i+1:02x}"},
            action_name="TheIngress.forward_eth_packet",
            action_params={"out_port": i+1}
        )
    switch.insertTableEntry(
        table_name="TheIngress.eth_exact",
        match_fields={"hdr.eth.dst": "ff:ff:ff:ff:ff:ff"},
        action_name="TheIngress.broadcast_eth_packet"
    )

    # Broadcast group for SML results
    switch.addMulticastGroup(mgid=1, ports=range(1, NUM_WORKERS+1))


topo = SMLTopo()
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()
CLI(net)
net.stop()