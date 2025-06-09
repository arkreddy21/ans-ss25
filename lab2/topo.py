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

from ipaddress import IPv4Address
from itertools import chain


# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type, ip):
		self.edges = []
		self.id = id
		self.type = type
		self.ip = ip

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		self.generate(num_ports)

	def generate(self, num_ports):

		k = num_ports
		# core switches
		for i in range((k//2)**2):
			self.switches.append(Node(f"s{i}", "core_switch", IPv4Address(f"10.{k}.{1 + i//(k//2)}.{1 + i%(k//2)}")))
		# pods
		for pod in range(k):
			for i in range(k//2):
				# edge switch (k/2 edge switches in each pod)
				self.switches.append(Node(f"s{len(self.switches)}", "edge_switch", IPv4Address(f"10.{pod}.{i}.1")))
				# create k/2 servers and connect them to edge switch
				for j in range(k//2):
					self.servers.append(Node(f"h{len(self.servers)}", "server", IPv4Address(f"10.{pod}.{i}.{2+j}")))
					self.switches[-1].add_edge(self.servers[-1])
			for i in range(k//2):
				# aggregation switch (k/2 aggr switches in each pod)
				n = Node(f"s{len(self.switches)}", "aggr_switch", IPv4Address(f"10.{pod}.{k//2 + i}.1"))
				self.switches.append(n)
				#link to edge switches
				for edge_switch in self.switches[-(k//2)-1-i : -1-i]:
					edge_switch.add_edge(self.switches[-1])
				#link to core switches
				for core_switch in self.switches[i*(k//2) : (i + 1)*(k//2)]:
					core_switch.add_edge(self.switches[-1])

	def node_by_ip(self, ip: IPv4Address) -> Node:
		for node in chain(self.servers, self.switches):
			if ip == node.ip:
				return node

	def print_topology_stats(self, k):
	
		print(f"=== Fat Tree Topology Statistics (k={k}) ===")
	
		# Basic counts
		core_switches = [s for s in self.switches if s.type == "core_switch"]
		aggr_switches = [s for s in self.switches if s.type == "aggr_switch"]
		edge_switches = [s for s in self.switches if s.type == "edge_switch"]
		print("\nNode Counts:")
		print(f"  Core switches: {len(core_switches)} (expected: {(k//2)**2})")
		print(f"  Aggregation switches: {len(aggr_switches)} (expected: {k*(k//2)})")
		print(f"  Edge switches: {len(edge_switches)} (expected: {k*(k//2)})")
		print(f"  Servers: {len(self.servers)} (expected: {k**3//4})")
	
		# Degree analysis
		print("\nDegree Analysis:")
		for switch_type, switches in [("Core", core_switches), ("Aggregation", aggr_switches), ("Edge", edge_switches)]:
			degrees = [len(s.edges) for s in switches]
			print(f"  {switch_type} switches - degrees: {set(degrees)}")
		server_degrees = [len(s.edges) for s in self.servers]
		print(f"  Servers - degrees: {set(server_degrees)}")
	
		# Connectivity checks
		print("\nConnectivity Checks:")
	
		# Check core-to-aggregation connections
		core_aggr_links = 0
		for core in core_switches:
			aggr_neighbors = [n for e in core.edges for n in [e.lnode, e.rnode] 
							 if n != core and n.type == "aggr_switch"]
			core_aggr_links += len(aggr_neighbors)
		print(f"  Core-to-Aggregation links: {core_aggr_links} (expected: {k * (k//2)**2})")
	
		# Check aggregation-to-edge connections
		aggr_edge_links = 0
		for aggr in aggr_switches:
			edge_neighbors = [n for e in aggr.edges for n in [e.lnode, e.rnode] 
							 if n != aggr and n.type == "edge_switch"]
			aggr_edge_links += len(edge_neighbors)
		print(f"  Aggregation-to-Edge links: {aggr_edge_links} (expected: {k * (k//2)**2})")
	
		# Check edge-to-server connections
		edge_server_links = 0
		for edge in edge_switches:
			server_neighbors = [n for e in edge.edges for n in [e.lnode, e.rnode] 
							   if n != edge and n.type == "server"]
			edge_server_links += len(server_neighbors)
		print(f"  Edge-to-Server links: {edge_server_links} (expected: {k * (k//2)**2})")
	
		total_links = sum(len(node.edges) for node in chain(self.servers, self.switches)) // 2
		expected_links = (k**3//4) * 3
		print(f"  Total Links: {total_links} (expected: {expected_links})")

		for switch_type, switches in [("Core", core_switches), ("Aggregation", aggr_switches), ("Edge", edge_switches)]:
			print(f"\n{switch_type} switches")
			for i, switch in enumerate(switches):
				neighbors = []
				for edge in switch.edges:
					neighbor = edge.rnode if edge.lnode == switch else edge.lnode
					neighbors.append(neighbor.id)
				print(f"  {switch.id}: connected to {neighbors}")
	
		print("\n=== End Statistics ===")
	