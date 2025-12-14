#include <core.p4>
#include <v1model.p4>

#define MAX_HOP_COUNT 8
#define INT_INSTRUCTIONS_MASK 0x00FF
#define TYPE_INT 0xFA
#define PROTOCOL_IPV4 0x0800
#define PROTOCOL_SCTP 132
#define NGAP_PORT 38412
#define PPID_NGAP 60

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

header sctp_common_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> verification_tag;
    bit<32> checksum;
}

header sctp_chunk_t {
    bit<8>  type;
    bit<8>  flags;
    bit<16> length;
}

header sctp_data_chunk_t {
    bit<32> tsn;
    bit<16> stream_id;
    bit<16> stream_seq;
    bit<32> payload_protocol_id;
}

header int_shim_t {
    bit<8>  type;
    bit<8>  reserved;
    bit<16> length;
    bit<16> next_proto;
}

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
    bit<8>  should_insert_int;
    bit<16> sctp_src_port;
    bit<16> sctp_dst_port;
    bit<8>  is_ngap_traffic;
}

struct headers {
    ethernet_t ethernet;
    int_shim_t int_shim;
    int_header_t int_header;
    int_md_t  int_md;
    ipv4_t     ipv4;
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
        meta.is_int_packet = 0;
        meta.is_ngap_traffic = 0;
        meta.should_insert_int = 0;
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_SCTP: parse_sctp_common;
            default: accept;
        }
    }

    state parse_sctp_common {
        packet.extract(hdr.sctp);
        meta.sctp_src_port = hdr.sctp.src_port;
        meta.sctp_dst_port = hdr.sctp.dst_port;
        
        // Check if this is NG-RAN to AMF traffic
        if (hdr.sctp.dst_port == NGAP_PORT) {
            meta.is_ngap_traffic = 1;
        }
        transition parse_sctp_chunk;
    }

    state parse_sctp_chunk {
        packet.extract(hdr.sctp_chunk);
        transition select(hdr.sctp_chunk.type) {
            0x00: parse_sctp_data_chunk;
            default: accept;
        }
    }

    state parse_sctp_data_chunk {
        packet.extract(hdr.sctp_data_chunk);
        transition accept;
    }
}

/********** INGRESS PIPELINE **********/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action int_source_action() {
        // Mark that we should insert INT
        meta.should_insert_int = 1;
    }

    action do_insert_int() {
        // Store original Ethernet type
        bit<16> original_ether_type = hdr.ethernet.etherType;

        // Change Ethernet type to INT
        hdr.ethernet.etherType = TYPE_INT;

        // Set INT shim header
        hdr.int_shim.setValid();
        hdr.int_shim.type = 1;
        hdr.int_shim.reserved = 0;
        hdr.int_shim.length = 44;
        hdr.int_shim.next_proto = original_ether_type;

        // Set INT header
        hdr.int_header.setValid();
        hdr.int_header.version = 1;
        hdr.int_header.d = 0;
        hdr.int_header.q = 0;
        hdr.int_header.m = 1;
        hdr.int_header.reserved1 = 0;
        hdr.int_header.hop_ml = 1;
        hdr.int_header.instruction = INT_INSTRUCTIONS_MASK;
        hdr.int_header.reserved2 = 0;
        hdr.int_header.remaining_hop_cnt = MAX_HOP_COUNT - 1;

        // Add metadata block
        hdr.int_md.setValid();
        hdr.int_md.switch_id = meta.switch_id;
        hdr.int_md.ingress_port_id = (bit<16>)meta.ingress_port;
        hdr.int_md.ingress_timestamp = meta.ingress_ts;
        hdr.int_md.egress_port_id = 0;
        hdr.int_md.hop_latency = 0;
        hdr.int_md.egress_timestamp = 0;
        hdr.int_md.queue_occupancy = 0;
        hdr.int_md.congestion_notification = 0;
        hdr.int_md.reserved1 = 0;
        hdr.int_md.reserved2 = 0;
    }

    action forward_action(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // Table for INT insertion - only for NG-RAN to AMF traffic
    table int_source_table {
        key = {
            meta.is_ngap_traffic: exact;
        }
        actions = {
            int_source_action;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward_action;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        meta.switch_id = 1;

        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            // Apply INT insertion for NG-RAN to AMF traffic
            if (hdr.ipv4.protocol == PROTOCOL_SCTP && hdr.sctp.isValid()) {
                int_source_table.apply();
            }
            
            // Apply forwarding
            ipv4_lpm.apply();
            
            // Insert INT headers if marked
            if (meta.should_insert_int == 1) {
                do_insert_int();
            }
        }
    }
}

/********** EGRESS PIPELINE **********/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action update_int_metadata() {
        if (hdr.int_md.isValid()) {
            hdr.int_md.egress_port_id = (bit<16>)standard_metadata.egress_port;
            hdr.int_md.egress_timestamp = (bit<32>)standard_metadata.egress_global_timestamp;
            hdr.int_md.hop_latency = hdr.int_md.egress_timestamp - hdr.int_md.ingress_timestamp;
            hdr.int_md.queue_occupancy = (bit<32>)standard_metadata.enq_qdepth;
        }
    }

    apply {
        if (hdr.int_shim.isValid()) {
            update_int_metadata();
        }
    }
}

/********** CHECKSUM VERIFY/COMPUTE **********/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/********** DEPARSER **********/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Always emit Ethernet
        packet.emit(hdr.ethernet);
        
        // Emit INT headers if valid - deparser will handle validity automatically
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_md);
        
        // Emit inner packet headers
        packet.emit(hdr.ipv4);
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
