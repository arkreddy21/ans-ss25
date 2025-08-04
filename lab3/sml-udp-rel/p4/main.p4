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

typedef bit<8> rank_t; /* Worker Rank */
typedef bit<2048> chunk_t; /* Chunk size 64*32 */

const bit<8> n_workers = 4;
const mac_addr_t sml_mac = 0x08000000ffff;
const ipv4_addr_t sml_ip = 0x0a000101;
const bit<16> sml_port = 50505;

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
  rank_t rank;
  bit<8> chunk_id;
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
      sml_port: parse_sml;
      default: accept;
    }
  }

  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
}

bool check_first_arrival(register<bit<8>> bitmap, in rank_t rank) {
  bit<8> old_value;
  @atomic {
    bitmap.read(old_value, 0);
    bit<8> new_value = old_value | (8w1 << rank);
    bitmap.write(0, new_value);
  };
  return (old_value & (8w1 << rank)) == 0;
}

bool check_all_completed(register<bit<8>> bitmap, in rank_t rank) {
  bit<8> new_value;
  @atomic {
    bit<8> old_value;
    bitmap.read(old_value, 0);
    new_value = old_value | (8w1 << rank);
    bitmap.write(0, new_value);
  };
  return new_value == 8w0x0f;
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
  register<bit<8>>(1) worker_bitmap;
  register<chunk_t>(1) aggregate_buffer;
  register<bit<8>>(1) aggregate_status;
  register<bit<8>>(1) chunk_id;
  register<chunk_t>(1) prev_aggregate_chunk;

  apply {
    if (standard_metadata.checksum_error == 1 || !hdr.eth.isValid()) {
      mark_to_drop(standard_metadata);
    }
    else if (hdr.arp.isValid() && hdr.arp.operation == 1 && hdr.arp.target_ip == sml_ip) {
      // MAC address requested for SwitchML. Send back ARP response
      hdr.arp.operation = 2;
      hdr.arp.target_mac = hdr.arp.sender_mac;
      hdr.arp.target_ip = hdr.arp.sender_ip;
      hdr.arp.sender_mac = sml_mac;
      hdr.arp.sender_ip = sml_ip;
      hdr.eth.dst = hdr.eth.src;
      hdr.eth.src = sml_mac;
      standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    else if (hdr.sml.isValid() && hdr.eth.dst == sml_mac && hdr.ipv4.dst_addr == sml_ip) {

      // Workers acknowledging final result
      if(hdr.sml.chunk_id == 0xff) {
        chunk_id.write(0, 0);  // reset chunk_id to start next iteration
        hdr.eth.dst = hdr.eth.src;
        hdr.eth.src = sml_mac;
        hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = sml_ip;
        hdr.sml.rank = 0xff;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        return;
      }

      bit<8> current_chunk_id;
      chunk_id.read(current_chunk_id, 0);

      // Worker sent a chunk of previous round. Send previous result.
      if(hdr.sml.chunk_id - current_chunk_id != 0) {
          hdr.eth.dst = hdr.eth.src;
          hdr.eth.src = sml_mac;
          hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
          hdr.ipv4.src_addr = sml_ip;
          prev_aggregate_chunk.read(hdr.sml.chunk, 0);
          hdr.sml.rank = 0xff;
          standard_metadata.egress_spec = standard_metadata.ingress_port;
          return;
      }

      // Check if this is the first packet from this worker.
      if (!check_first_arrival(worker_bitmap, hdr.sml.rank)) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Accumulate
      chunk_t old_value;
      chunk_t new_value;
      @atomic {
        aggregate_buffer.read(old_value, 0);
        new_value = old_value + hdr.sml.chunk;
        aggregate_buffer.write(0, new_value);
      }

      // Check if all the chunks in this round are accumulated
      if (!check_all_completed(aggregate_status, hdr.sml.rank)) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Accumulation done. Broadcast result and reset memory
      hdr.sml.chunk = new_value;
      standard_metadata.mcast_grp = 1;
      worker_bitmap.write(0, 0);
      aggregate_status.write(0, 0);
      aggregate_buffer.write(0, 0);
      prev_aggregate_chunk.write(0, new_value);
      chunk_id.write(0, current_chunk_id+1);
    }
    else {
      mark_to_drop(standard_metadata);
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
    }
    if (hdr.sml.isValid()) {
      hdr.sml.rank = 0xff;
      hdr.eth.src = sml_mac;
      hdr.ipv4.src_addr = sml_ip;
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
        hdr.sml.rank, hdr.sml.chunk_id, hdr.sml.chunk
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
        hdr.sml.rank, hdr.sml.chunk_id, hdr.sml.chunk
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