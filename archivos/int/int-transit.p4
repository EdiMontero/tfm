#include <core.p4>
#include <v1model.p4>

#define MAX_HOP_COUNT 8
#define INT_INSTRUCTIONS_MASK 0x00FF
#define TYPE_INT 0xFA
#define PROTOCOL_IPV4 0x0800
#define PROTOCOL_SCTP 132

/********** HEADER DEFINITIONS **********/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// SCTP Common Header
header sctp_common_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> verification_tag;
    bit<32> checksum;
}

// SCTP Chunk Header (common for all chunks)
header sctp_chunk_t {
    bit<8>  type;
    bit<8>  flags;
    bit<16> length;
}

// SCTP DATA Chunk (specific fields)
header sctp_data_chunk_t {
    bit<32> tsn;
    bit<16> stream_id;
    bit<16> stream_seq;
    bit<32> payload_protocol_id;
}

// INT Shim Header (4 bytes)
header int_shim_t {
    bit<8>  type;
    bit<8>  reserved;
    bit<16> length;
    bit<16> next_proto;
}

// INT Header (8 bytes)
header int_header_t {
    bit<4>  version;
    bit<2>  d;
    bit<2>  q;
    bit<5>  m;
    bit<3>  reserved1;
    bit<8>  hop_ml;
    bit<16> instruction;
    bit<8>  reserved2;
    bit<8>  remaining_hop_cnt;
}

// INT Metadata (32 bytes - one block)
header int_md_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<32> hop_latency;
    bit<32> queue_occupancy;
    bit<32> ingress_timestamp;
    bit<32> egress_timestamp;
    bit<8>  congestion_notification;
    bit<8>  reserved1;
    bit<16> reserved2;
}

/********** METADATA STRUCTURES **********/
struct metadata {
    bit<32> switch_id;
    bit<9>  ingress_port;
    bit<32> ingress_ts;
    bit<32> egress_ts;
    bit<8>  is_int_packet;
    bit<9>  clone_port;
    bit<32> queue_occupancy;
    bit<8> md_blocks_extracted;
}

struct headers {
    // Outer headers
    ethernet_t ethernet;

    // INT headers
    int_shim_t int_shim;
    int_header_t int_header;
    int_md_t  int_md[MAX_HOP_COUNT];

    // Inner headers (original encapsulated packet)
    ipv4_t     ipv4_inner;
    sctp_common_t sctp;
    sctp_chunk_t sctp_chunk;
    sctp_data_chunk_t sctp_data_chunk;
}

/********** PARSER **********/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        meta.ingress_port = standard_metadata.ingress_port;
        meta.ingress_ts = (bit<32>)standard_metadata.ingress_global_timestamp;
        meta.md_blocks_extracted = 0;
        meta.is_int_packet = 0;
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0xFA: parse_int_shim;
            default: accept;
        }
    }

    // For non-INT IPv4 packets (shouldn't happen in transit)
    state parse_ipv4 {
        packet.extract(hdr.ipv4_inner);
        transition select(hdr.ipv4_inner.protocol) {
            PROTOCOL_SCTP: parse_sctp_common;
            default: accept;
        }
    }

    state parse_sctp_common {
        packet.extract(hdr.sctp);
        transition parse_sctp_chunk;
    }

    state parse_sctp_chunk {
        packet.extract(hdr.sctp_chunk);
        transition select(hdr.sctp_chunk.type) {
            0x00: parse_sctp_data_chunk; // DATA chunk
            default: accept;
        }
    }

    state parse_sctp_data_chunk {
        packet.extract(hdr.sctp_data_chunk);
        transition accept;
    }

    // INT parsing path
    state parse_int_shim {
        packet.extract(hdr.int_shim);
        meta.is_int_packet = 1;
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        // Calculate how many metadata blocks to extract
        meta.md_blocks_extracted = hdr.int_header.hop_ml - hdr.int_header.remaining_hop_cnt;
        transition parse_int_metadata;
    }

    state parse_int_metadata {
        // Extract existing metadata blocks
        // SW1 sent 1 block, so we extract 1 block
        packet.extract(hdr.int_md[0]);
        transition parse_encapsulated_protocol;
    }

    state parse_encapsulated_protocol {
        transition select(hdr.int_shim.next_proto) {
            0x0800: parse_encapsulated_ipv4;
            default: accept;
        }
    }

    state parse_encapsulated_ipv4 {
        packet.extract(hdr.ipv4_inner);
        transition select(hdr.ipv4_inner.protocol) {
            PROTOCOL_SCTP: parse_encapsulated_sctp_common;
            default: accept;
        }
    }

    state parse_encapsulated_sctp_common {
        packet.extract(hdr.sctp);
        transition parse_encapsulated_sctp_chunk;
    }

    state parse_encapsulated_sctp_chunk {
        packet.extract(hdr.sctp_chunk);
        transition select(hdr.sctp_chunk.type) {
            0x00: parse_encapsulated_sctp_data_chunk;
            default: accept;
        }
    }

    state parse_encapsulated_sctp_data_chunk {
        packet.extract(hdr.sctp_data_chunk);
        transition accept;
    }
}

/********** INGRESS PIPELINE **********/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action forward_action(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4_inner.dstAddr: lpm;
        }
        actions = {
            forward_action;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        meta.switch_id = 2;

        if (hdr.int_shim.isValid()) {
            if (hdr.int_header.remaining_hop_cnt > 0) {
                // SW1 already used int_md[0], we add SW2 in int_md[1]
                hdr.int_md[1].setValid();
                hdr.int_md[1].switch_id = meta.switch_id;
                hdr.int_md[1].ingress_port_id = (bit<16>)meta.ingress_port;
                hdr.int_md[1].ingress_timestamp = meta.ingress_ts;
                hdr.int_md[1].egress_port_id = 0;
                hdr.int_md[1].hop_latency = 0;
                hdr.int_md[1].egress_timestamp = 0;
                hdr.int_md[1].queue_occupancy = 0;
                hdr.int_md[1].congestion_notification = 0;
                hdr.int_md[1].reserved1 = 0;
                hdr.int_md[1].reserved2 = 0;

                hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
                hdr.int_shim.length = hdr.int_shim.length + 32;
            }
        }

        if (hdr.ipv4_inner.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/********** EGRESS PIPELINE **********/
control MyEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    apply {
        if (hdr.int_shim.isValid()) {
            // Update SW2 metadata (position 1)
            if (hdr.int_md[1].isValid() && hdr.int_md[1].egress_port_id == 0) {
                hdr.int_md[1].egress_port_id = (bit<16>)standard_metadata.egress_port;
                hdr.int_md[1].egress_timestamp = (bit<32>)standard_metadata.egress_global_timestamp;
                hdr.int_md[1].hop_latency = hdr.int_md[1].egress_timestamp - hdr.int_md[1].ingress_timestamp;
                hdr.int_md[1].queue_occupancy = (bit<32>)standard_metadata.enq_qdepth;
            }
        }
    }
}

/********** CHECKSUM VERIFY/COMPUTE **********/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply {} }

/********** DEPARSER **********/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);

        // Emit all INT metadata blocks
        packet.emit(hdr.int_md[0]);
        packet.emit(hdr.int_md[1]);
        packet.emit(hdr.int_md[2]);
        packet.emit(hdr.int_md[3]);
        packet.emit(hdr.int_md[4]);
        packet.emit(hdr.int_md[5]);
        packet.emit(hdr.int_md[6]);
        packet.emit(hdr.int_md[7]);

        packet.emit(hdr.ipv4_inner);
        packet.emit(hdr.sctp);
        packet.emit(hdr.sctp_chunk);
        packet.emit(hdr.sctp_data_chunk);
    }
}

/********** SWITCH **********/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
