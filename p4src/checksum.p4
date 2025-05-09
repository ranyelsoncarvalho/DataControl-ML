#ifndef CHECKSUM_P4
#define CHECKSUM_P4

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
        if (hdr.ipv4.isValid()) {
            verify_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16
            );
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
        if (hdr.ipv4.isValid()) {
            update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16
            );
        }
    }
}

#endif
