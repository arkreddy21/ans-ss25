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
typedef bit<8> worker_id_t; /*< Worker IDs */

typedef bit<2048> chunk_t; /* Chunk size 64*32 */

const worker_id_t n_workers = 8;
const mac_addr_t accumulator_mac = 0x08000000ffff;

/******** Headers ********/

header ethernet_t {
  mac_addr_t dst;
  mac_addr_t src;
  bit<16> ether_type;
}

header sml_t {
  worker_id_t rank;
  chunk_t chunk;
}

struct headers {
  ethernet_t eth;
  sml_t sml;
}

struct metadata { /* empty */ }

/******** Parser ********/

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
      0x88b5: parse_sml;
      default: accept;
    }
  }

  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
}

/******** Ingress Processing ********/

tuple<bool, bool> atomic_bitmap_action(register<bit<64>> bitmap, in worker_id_t i_worker) {
  bit<64> old_bitmap_value;
  bit<64> new_bitmap_value;
  @atomic {
    bitmap.read(old_bitmap_value, 0);
    new_bitmap_value = old_bitmap_value | (64w1 << i_worker);
    bitmap.write(0, new_bitmap_value);
  };
  // check if entry from this worker is valid (not a duplicate)
  bool valid_entry = (old_bitmap_value & (64w1 << i_worker)) == 0;
  // check if this is the last worker for this round
  bool last_entry = new_bitmap_value == ((64w1 << n_workers) - 1); 
  return { valid_entry, last_entry };
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

  register<bit<64>>(1) arrival_bitmap;
  register<chunk_t>(1) accumulated_chunk;
  register<bit<64>>(1) completion_bitmap;

  apply {
    if(!hdr.eth.isValid()) {
      mark_to_drop(standard_metadata);
      return;
    }
    if(!(hdr.eth.dst == accumulator_mac)) {
      eth_exact.apply();
      return;
    }
    if(hdr.sml.isValid()) {
      // Check that this is the first packet from this worker.
      tuple<bool, bool> arrival_result = atomic_bitmap_action(arrival_bitmap, hdr.sml.rank);
      if (!arrival_result[0]) {
        mark_to_drop(standard_metadata);
        return;
      }
      
      // Accumulate
      @atomic {
        bit<2048> old_value;
        accumulated_chunk.read(old_value, 0);
        bit<2048> new_value = old_value + hdr.sml.chunk;
        accumulated_chunk.write(0, new_value);
      }

      // Check whether this chunk is the last one for this round
      tuple<bool, bool> accum_result = atomic_bitmap_action(completion_bitmap, hdr.sml.rank);
      if (!accum_result[1]) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Last Accumulation. Load result and reset memory.
      accumulated_chunk.read(hdr.sml.chunk, 0);
      arrival_bitmap.write(0, 0);
      completion_bitmap.write(0, 0);
      accumulated_chunk.write(0, 0);

      // Broadcast result
      standard_metadata.mcast_grp = 1;
    }
  }
}

/******** Egress Processing ********/

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  apply {
    if (standard_metadata.mcast_grp == 1) {
      hdr.eth.dst = 0xffffffffffff;
      // Broadcasting an accumulation result.
      if(hdr.sml.isValid()) {
        hdr.sml.rank = 0xff;
        hdr.eth.src = accumulator_mac;
      }
    }
  }
}

/******** Checksum ********/

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply {
    /* Implement me (if needed) */
  }
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    /* Implement me (if needed) */
  }
}

/******** Deparser ********/

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.eth);
    packet.emit(hdr.sml);
  }
}

/******** Switch ********/

V1Switch(
  TheParser(),
  TheChecksumVerification(),
  TheIngress(),
  TheEgress(),
  TheChecksumComputation(),
  TheDeparser()
) main;