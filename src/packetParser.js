// ============================================================================
// packetParser.js - Network packet parser (Ethernet → IPv4 → TCP/UDP)
// Converted from: include/packet_parser.h + src/packet_parser.cpp
// ============================================================================

'use strict';

// ============================================================================
// Constants
// ============================================================================

const ETHER_TYPE_IPV4 = 0x0800;

const ETH_HEADER_LEN     = 14;
const MIN_IP_HEADER_LEN  = 20;
const MIN_TCP_HEADER_LEN = 20;
const UDP_HEADER_LEN     = 8;

// ============================================================================
// Helpers
// ============================================================================

/**
 * Format 6 bytes starting at `offset` as a colon-separated hex MAC string.
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {string}  e.g. "aa:bb:cc:dd:ee:ff"
 */
function formatMac(buf, offset) {
    const parts = [];
    for (let i = 0; i < 6; i++) {
        parts.push(buf[offset + i].toString(16).padStart(2, '0'));
    }
    return parts.join(':');
}

/**
 * Convert a 32-bit big-endian IP integer to dotted-decimal string.
 * @param {number} ip  Value obtained via buf.readUInt32BE().
 * @returns {string}  e.g. "192.168.1.1"
 */
function ipToString(ip) {
    return `${(ip >>> 24) & 0xFF}.${(ip >>> 16) & 0xFF}.${(ip >>> 8) & 0xFF}.${ip & 0xFF}`;
}

// ============================================================================
// Main parser
// ============================================================================

/**
 * Parse a raw Ethernet frame from a Buffer.
 *
 * Returns a parsed packet object, or null if the packet is not IPv4 or
 * is too short to parse.
 *
 * @param {Buffer} data  Raw Ethernet frame bytes.
 * @returns {object|null}
 */
function parsePacket(data) {
    const len = data.length;

    // --- Ethernet header (bytes 0-13) ------------------------------------

    if (len < ETH_HEADER_LEN) return null;

    const dstMac    = formatMac(data, 0);
    const srcMac    = formatMac(data, 6);
    const etherType = data.readUInt16BE(12);

    // Only parse IPv4
    if (etherType !== ETHER_TYPE_IPV4) return null;

    // --- IPv4 header (starts at offset 14) --------------------------------

    const ipStart = ETH_HEADER_LEN; // 14

    if (len < ipStart + MIN_IP_HEADER_LEN) return null;

    const versionIhl  = data[ipStart];
    const ipVersion   = (versionIhl >> 4) & 0x0F;
    const ihl         = versionIhl & 0x0F;          // header length in 32-bit words
    const ipHeaderLen = ihl * 4;                     // header length in bytes

    if (ipVersion !== 4) return null;
    if (ipHeaderLen < MIN_IP_HEADER_LEN) return null;
    if (len < ipStart + ipHeaderLen) return null;

    const ttl      = data[ipStart + 8];
    const protocol = data[ipStart + 9];

    // Source IP at IP offset 12, dest IP at IP offset 16
    const srcIpRaw = data.readUInt32BE(ipStart + 12);
    const dstIpRaw = data.readUInt32BE(ipStart + 16);
    const srcIp    = ipToString(srcIpRaw);
    const dstIp    = ipToString(dstIpRaw);

    // --- Transport layer --------------------------------------------------

    const transportStart = ipStart + ipHeaderLen;

    let srcPort       = 0;
    let dstPort       = 0;
    let tcpFlags      = 0;
    let tcpSeq        = 0;
    let tcpAck        = 0;
    let hasTcp        = false;
    let hasUdp        = false;
    let payloadOffset = transportStart;

    if (protocol === 6) {
        // TCP
        if (len < transportStart + MIN_TCP_HEADER_LEN) return null;

        srcPort = data.readUInt16BE(transportStart);
        dstPort = data.readUInt16BE(transportStart + 2);
        tcpSeq  = data.readUInt32BE(transportStart + 4);
        tcpAck  = data.readUInt32BE(transportStart + 8);

        const dataOffset   = (data[transportStart + 12] >> 4) & 0x0F;
        const tcpHeaderLen = dataOffset * 4;

        tcpFlags = data[transportStart + 13];

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN) return null;
        if (len < transportStart + tcpHeaderLen) return null;

        hasTcp        = true;
        payloadOffset = transportStart + tcpHeaderLen;

    } else if (protocol === 17) {
        // UDP
        if (len < transportStart + UDP_HEADER_LEN) return null;

        srcPort = data.readUInt16BE(transportStart);
        dstPort = data.readUInt16BE(transportStart + 2);

        hasUdp        = true;
        payloadOffset = transportStart + UDP_HEADER_LEN;
    }

    // --- Payload ----------------------------------------------------------

    const payloadLength = payloadOffset < len ? len - payloadOffset : 0;

    return {
        srcMac,
        dstMac,
        etherType,
        srcIp,
        dstIp,
        protocol,
        ttl,
        srcPort,
        dstPort,
        tcpFlags,
        tcpSeq,
        tcpAck,
        hasTcp,
        hasUdp,
        payloadOffset,
        payloadLength,
    };
}

// ============================================================================
// Exports
// ============================================================================
module.exports = { parsePacket };
