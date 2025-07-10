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
typedef bit<8> rank_t;       /* Worker Rank */
typedef bit<2048> chunk_t;   /* Chunk size 64*32 */

const bit<8> n_workers = 8;
const mac_addr_t sml_mac = 0x08000000ffff;

/******** Headers ********/

header ethernet_t {
  mac_addr_t dst;
  mac_addr_t src;
  bit<16> ether_type;
}

header sml_t {
  rank_t rank;
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
  return new_value == 8w0xff;
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
  register<bit<8>>(1) worker_bitmap;
  register<chunk_t>(1) aggregate_buffer;
  register<bit<8>>(1) aggregate_status;

  apply {
    if (hdr.eth.isValid() && hdr.sml.isValid() && hdr.eth.dst == sml_mac) {
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
    }
    else {
      mark_to_drop(standard_metadata);
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
    }
    if (hdr.sml.isValid()) {
      hdr.sml.rank = 0xff;
      hdr.eth.src = sml_mac;
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