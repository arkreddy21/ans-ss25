/*
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
*/



#include <core.p4>
#include <v1model.p4>

typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
typedef bit<32> ipv4_addr_t;  /*< IPv4 address */

typedef bit<8> worker_id_t; /*< Worker IDs */
typedef bit<2048> chunk_t; /* Chunk size 64*32 */

const worker_id_t n_workers = 8;
const mac_addr_t accumulator_mac = 0x08000000ffff;
const ipv4_addr_t accumulator_ip = 0x0a000101;
const bit<16> accumulator_port = 50505;

header ethernet_t {
  mac_addr_t dst;
  mac_addr_t src;
  bit<16> ether_type;
}

header arp_t {
  bit<16> htype;
  bit<16> ptype;
  bit<8> hlen;
  bit<8> plen;
  bit<16> operation;
  mac_addr_t sender_mac;
  ipv4_addr_t sender_ip;
  mac_addr_t target_mac;
  ipv4_addr_t target_ip;
}

header ipv4_t {
  bit<4> version;
  bit<4> ihl;
  bit<6> dscp;
  bit<2> ecn;
  bit<16> len;
  bit<16> ident;
  bit<2> flags;
  bit<14> fragment_offset;
  bit<8> ttl;
  bit<8> protocol;
  bit<16> checksum;
  ipv4_addr_t src_addr;
  ipv4_addr_t dst_addr;
}

header udp_t {
  bit<16> src_port;
  bit<16> dst_port;
  bit<16> len;
  bit<16> checksum;
}

header sml_t {
  worker_id_t rank;
  chunk_t chunk;
}

struct headers {
  ethernet_t eth;
  arp_t arp;
  ipv4_t ipv4;
  udp_t udp;
  sml_t sml;
}

struct metadata { /* empty */ }

parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  state start {
    transition parse_eth;
  }

  state parse_eth {
    packet.extract(hdr.eth);
    transition select(hdr.eth.ether_type) {
      0x800: parse_ipv4;
      0x806: parse_arp;
      default: accept;
    }
  }

  state parse_arp {
    packet.extract(hdr.arp);
    transition accept;
  }

  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      17: parse_udp;
      default: accept;
    }
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition select(hdr.udp.dst_port) {
      accumulator_port: parse_sml;
      default: accept;
    }
  }

  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
}


bool check_first_arrival(register<bit<32>> bitmap, in worker_id_t i_worker) {
  bit<32> old_bitmap_value;
  @atomic {
    bitmap.read(old_bitmap_value, 0);
    bit<32> new_bitmap_value = old_bitmap_value | (32w1 << i_worker);
    bitmap.write(0, new_bitmap_value);
  };
  return (old_bitmap_value & (32w1 << i_worker)) == 0;
}

bool check_all_completed(register<bit<32>> bitmap, in worker_id_t i_worker) {
  bit<32> new_bitmap_value;
  @atomic {
    bit<32> old_bitmap_value;
    bitmap.read(old_bitmap_value, 0);
    new_bitmap_value = old_bitmap_value | (32w1 << i_worker);
    bitmap.write(0, new_bitmap_value);
  };
  return new_bitmap_value == ((32w1 << n_workers) - 1);
}


control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
  action forward_eth_packet(sw_port_t out_port) {
    standard_metadata.egress_spec = out_port;
  }

  action broadcast_eth_packet() {
    standard_metadata.mcast_grp = 1;
  }

  action drop_eth_packet() {
    mark_to_drop(standard_metadata);
  }

  table eth_exact {
    key = {
      hdr.eth.dst: exact;
    }
    actions = {
      forward_eth_packet;
      broadcast_eth_packet;
      drop_eth_packet;
    }
    default_action = drop_eth_packet();
  }

  register<bit<32>>(1) arrival_bitmap;
  register<chunk_t>(1) accumulated_chunk;
  register<bit<32>>(1) completion_bitmap;

  apply {
    if (standard_metadata.checksum_error == 1 || !hdr.eth.isValid()) {
      mark_to_drop(standard_metadata);
    }
    else if (hdr.arp.isValid() && hdr.arp.operation == 1 && hdr.arp.target_ip == accumulator_ip) {
      // Accumulator's MAC address was requested
      standard_metadata.egress_spec = standard_metadata.ingress_port; // Reflect packet
      hdr.arp.operation = 2;
      hdr.arp.target_mac = hdr.arp.sender_mac;
      hdr.arp.target_ip = hdr.arp.sender_ip;
      hdr.arp.sender_mac = accumulator_mac;
      hdr.arp.sender_ip = accumulator_ip;
      hdr.eth.dst = hdr.eth.src;
      hdr.eth.src = accumulator_mac;
    }
    else if (hdr.sml.isValid() && hdr.eth.dst == accumulator_mac && hdr.ipv4.dst_addr == accumulator_ip) {
      // Check if this is the first packet from this worker.
      if (!check_first_arrival(arrival_bitmap, hdr.sml.rank)) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Accumulate
      @atomic {
        chunk_t old_value;
        accumulated_chunk.read(old_value, 0);
        chunk_t new_value = old_value + hdr.sml.chunk;
        accumulated_chunk.write(0, new_value);
      }

      // Check if all the chunks in this round are accumulated
      if (!check_all_completed(completion_bitmap, hdr.sml.rank)) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Broadcast result
      accumulated_chunk.read(hdr.sml.chunk, 0);
      standard_metadata.mcast_grp = 1;

      // Reset memory
      completion_bitmap.write(0, 0);
      accumulated_chunk.write(0, 0);
      arrival_bitmap.write(0, 0);
    }
    else {
      eth_exact.apply();
    }
  }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  apply {
    if (standard_metadata.mcast_grp == 1) {
      hdr.eth.dst = 0xffffffffffff;
      hdr.ipv4.dst_addr = 0xffffffff;
      // Broadcasting an accumulation result.
      if(hdr.sml.isValid()) {
        hdr.sml.rank = 0xff;
        hdr.eth.src = accumulator_mac;
        hdr.ipv4.src_addr = accumulator_ip;
      }
    }
  }
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply {
    verify_checksum(
      hdr.ipv4.isValid(),
      {
        hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.len,
        hdr.ipv4.ident, hdr.ipv4.flags, hdr.ipv4.fragment_offset,
        hdr.ipv4.ttl, hdr.ipv4.protocol,
        hdr.ipv4.src_addr, hdr.ipv4.dst_addr
      },
      hdr.ipv4.checksum,
      HashAlgorithm.csum16
    );

    verify_checksum_with_payload(
      hdr.udp.isValid() && hdr.sml.isValid(),
      {
        hdr.ipv4.src_addr, hdr.ipv4.dst_addr, 8w0, hdr.ipv4.protocol,
        hdr.udp.len, hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.len,
        hdr.sml.rank, hdr.sml.chunk
      },
      hdr.udp.checksum,
      HashAlgorithm.csum16
    );
  }
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    update_checksum(
      hdr.ipv4.isValid(),
      {
        hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.len,
        hdr.ipv4.ident, hdr.ipv4.flags, hdr.ipv4.fragment_offset,
        hdr.ipv4.ttl, hdr.ipv4.protocol,
        hdr.ipv4.src_addr, hdr.ipv4.dst_addr
      },
      hdr.ipv4.checksum,
      HashAlgorithm.csum16
    );

    update_checksum_with_payload(
      hdr.udp.isValid() && hdr.sml.isValid(),
      {
        hdr.ipv4.src_addr, hdr.ipv4.dst_addr, 8w0, hdr.ipv4.protocol,
        hdr.udp.len, hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.len,
        hdr.sml.rank, hdr.sml.chunk
      },
      hdr.udp.checksum,
      HashAlgorithm.csum16
    );
  }
}

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.eth);
    packet.emit(hdr.arp);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.udp);
    packet.emit(hdr.sml);
  }
}

V1Switch(
  TheParser(),
  TheChecksumVerification(),
  TheIngress(),
  TheEgress(),
  TheChecksumComputation(),
  TheDeparser()
) main;