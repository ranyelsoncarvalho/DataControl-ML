// ===========================
#include "define.p4"
#include "header.p4"
#include "parser.p4"
#include "checksum.p4"
#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_DDOSD 0xFD

const bit<32> MAX_FLOWS = 1024;

struct metadata_t {
    bit<32> flow_index;
}

// ===========================
// registers for statistics of flows
// ===========================

register<bit<32>>(MAX_FLOWS) reg_flow_duration;
register<bit<32>>(MAX_FLOWS) reg_total_fwd_packets;
register<bit<32>>(MAX_FLOWS) reg_total_bwd_packets;
register<bit<32>>(MAX_FLOWS) reg_total_len_fwd;
register<bit<32>>(MAX_FLOWS) reg_total_len_bwd;
register<bit<32>>(MAX_FLOWS) reg_fwd_header_length;
register<bit<32>>(MAX_FLOWS) reg_bwd_header_length;
register<bit<32>>(MAX_FLOWS) reg_fwd_iat_total;
register<bit<32>>(MAX_FLOWS) reg_bwd_iat_total;
register<bit<32>>(MAX_FLOWS) reg_packet_total_len;
register<bit<32>>(MAX_FLOWS) reg_packet_count;
register<bit<32>>(MAX_FLOWS) reg_syn_count;
register<bit<32>>(MAX_FLOWS) reg_rst_count;
register<bit<32>>(MAX_FLOWS) reg_ack_count;
register<bit<32>>(MAX_FLOWS) reg_urg_count;

// registers of control
register<bit<32>>(1) reg_flow_window_counter;

register<bit<32>>(MAX_FLOWS) reg_local_trust;
register<bit<1>>(MAX_FLOWS) reg_classification;
register<bit<32>>(1) reg_global_threshold;
register<bit<32>>(MAX_FLOWS) reg_block_timer;

// ===========================
// flow
// ===========================

action compute_flow_index() {
    bit<32> index;
    index = hash(
        HashAlgorithm.crc32,
        (bit<160>) {
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.tcp.isValid() ? hdr.tcp.srcPort : hdr.udp.srcPort,
            hdr.tcp.isValid() ? hdr.tcp.dstPort : hdr.udp.dstPort,
            hdr.ipv4.protocol
        },
        MAX_FLOWS
    );
    meta.flow_index = index;
}

// ===========================
// data collection
// ===========================

action update_tcp_stats() {
    reg_total_fwd_packets[meta.flow_index] = reg_total_fwd_packets[meta.flow_index] + 1;
    reg_total_len_fwd[meta.flow_index] = reg_total_len_fwd[meta.flow_index] + hdr.ipv4.totalLen;
    reg_packet_total_len[meta.flow_index] = reg_packet_total_len[meta.flow_index] + hdr.ipv4.totalLen;
    reg_packet_count[meta.flow_index] = reg_packet_count[meta.flow_index] + 1;

    reg_fwd_header_length[meta.flow_index] = reg_fwd_header_length[meta.flow_index] + hdr.tcp.dataOffset;
    reg_fwd_iat_total[meta.flow_index] = reg_fwd_iat_total[meta.flow_index] + 1;

    if (hdr.tcp.flags[1] == 1) {
        reg_syn_count[meta.flow_index] = reg_syn_count[meta.flow_index] + 1;
    }
    if (hdr.tcp.flags[2] == 1) {
        reg_rst_count[meta.flow_index] = reg_rst_count[meta.flow_index] + 1;
    }
    if (hdr.tcp.flags[4] == 1) {
        reg_ack_count[meta.flow_index] = reg_ack_count[meta.flow_index] + 1;
    }
    if (hdr.tcp.flags[5] == 1) {
        reg_urg_count[meta.flow_index] = reg_urg_count[meta.flow_index] + 1;
    }
}

action update_udp_stats() {
    reg_total_bwd_packets[meta.flow_index] = reg_total_bwd_packets[meta.flow_index] + 1;
    reg_total_len_bwd[meta.flow_index] = reg_total_len_bwd[meta.flow_index] + hdr.ipv4.totalLen;
    reg_packet_total_len[meta.flow_index] = reg_packet_total_len[meta.flow_index] + hdr.ipv4.totalLen;
    reg_packet_count[meta.flow_index] = reg_packet_count[meta.flow_index] + 1;

    reg_bwd_header_length[meta.flow_index] = reg_bwd_header_length[meta.flow_index] + 8;
    reg_bwd_iat_total[meta.flow_index] = reg_bwd_iat_total[meta.flow_index] + 1;
}

action increment_window_counter() { //observation window
    reg_flow_window_counter[0] = reg_flow_window_counter[0] + 1;

    if (reg_flow_window_counter[0] >= 100) {
        generate_report();  
        reg_flow_window_counter[0] = 0;
    }
}

// ===========================
// list management by actions for classification.py
// ===========================

action set_to_confidence() {
    standard_metadata.priority = 1;
}

action set_to_unprioritized() {
    standard_metadata.priority = 0;
}

action drop_packet() {
    mark_to_drop();
}

action decide_client_behavior() {
    bit<32> trust = reg_local_trust[meta.flow_index];
    bit<1> classif = reg_classification[meta.flow_index];
    bit<32> threshold = reg_global_threshold[0];
    bit<32> timer = reg_block_timer[meta.flow_index];

    if (classif == 0) {
        if (timer == 0) {
            reg_block_timer[meta.flow_index] = 1000;
        } else {
            reg_block_timer[meta.flow_index] = timer - 1;
            drop_packet();
            return;
        }
    } else {
        if (trust >= threshold) {
            set_to_confidence();
        } else {
            set_to_unprioritized();
        }
    }
}

// ===========================
// collection table
// ===========================

table flow_table {
    actions = {
        update_tcp_stats;
        update_udp_stats;
        NoAction;
    }
    size = MAX_FLOWS;
    default_action = NoAction();
}


// ===========================
// foward packets
// ===========================

action ipv4_forward(mac_addr dst_mac, bit<9> port) {
    hdr.ethernet.dstAddr = dst_mac;
    standard_metadata.egress_spec = port;
}

table ipv4_lpm {
    key = {
        hdr.ipv4.dstAddr: lpm;
    }
    actions = {
        ipv4_forward;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
}


// ===========================
// discard packets
// ===========================

action drop() {
    mark_to_drop();
}

table drop_table {
    key = {
        hdr.ipv4.srcAddr: exact;
    }
    actions = {
        drop;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
}

// ===========================
// ingress
// ===========================

control IngressImpl(inout headers hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            compute_flow_index();

            if (hdr.tcp.isValid()) {
                flow_table.apply(update_tcp_stats);
                increment_window_counter();
            } else if (hdr.udp.isValid()) {
                flow_table.apply(update_udp_stats);
                increment_window_counter();
            }

            decide_client_behavior();
            drop_table.apply();
            ipv4_lpm.apply();
        }
    }
}

// ===========================
// submission manager: report to controller
// ===========================

header report_t {
    ipv4_addr client_ip;
    bit<32> trust_value;
}

struct report_metadata_t {
    bit<32> report_flag;
}

// Report header instance
report_t report_hdr;
report_metadata_t report_meta;

action generate_report() { //clone packet
    report_hdr.client_ip = hdr.ipv4.srcAddr;
    report_hdr.trust_value = reg_local_trust[meta.flow_index];
    report_meta.report_flag = 1;
    clone(CloneType.I2E, 99);
}

control ReportDeparser(packet_out packet, in headers hdr) {
    apply {
        for (bit<32> i = 0; i < MAX_REPORTS; i++) {
            bit<32> ip;
            bit<32> trust;
            reg_report_ip.read(ip, i);
            reg_report_trust.read(trust, i);
            report_stack.entries[i].client_ip = ip;
            report_stack.entries[i].trust_value = trust;
        }

        for (bit<32> i = 0; i < MAX_REPORTS; i++) {
            packet.emit(report_stack.entries[i]);
        }
    }
}

control EgressImpl(inout headers hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t standard_metadata) {
    apply { }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        if (hdr.tcp.isValid()) {
            packet.emit(hdr.tcp);
        } else if (hdr.udp.isValid()) {
            packet.emit(hdr.udp);
        }
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    IngressImpl(),
    EgressImpl(),
    MyComputeChecksum(),
    ReportDeparser()
) main;
