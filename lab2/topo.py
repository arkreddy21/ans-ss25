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
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

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

		# TODO: code for generating the fat-tree topology
		# core switches
		for i in range((num_ports//2)**2):
			self.switches.append(Node(f"s{i}", "switch"))
		# pods
		for pod in range(num_ports):
			for i in range(num_ports//2):
				# edge switch (k/2 edge switches in each pod)
				self.switches.append(Node(f"s{len(self.switches)}", "switch"))
				# create and connect k/2 servers for each edge switch
				for j in range(num_ports//2):
					self.servers.append(Node(f"h{len(self.servers)}", "server"))
					self.switches[-1].add_edge(self.servers[-1])
			for i in range(num_ports//2):
				# aggregation switch (k/2 aggr switches in each pod)
				n = Node(f"s{len(self.switches)}", "switch")
				self.switches.append(n)
				#link to edge switches
				for edge_switch in self.switches[-(num_ports//2)-1-i : -1-i]:
					edge_switch.add_edge(self.switches[-1])
				#link to core switches
				for core_switch in self.switches[i*(num_ports//2) : (i + 1)*(num_ports//2)]:
					core_switch.add_edge(self.switches[-1])
