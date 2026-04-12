// ============================================================================
// pcapReader.js - PCAP file reader
// Converted from: include/pcap_reader.h + src/pcap_reader.cpp
// ============================================================================

'use strict';

const fs = require('fs');

// Magic numbers for PCAP files
const PCAP_MAGIC_NATIVE  = 0xa1b2c3d4; // Native byte order
const PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // Swapped byte order

// Header sizes
const GLOBAL_HEADER_SIZE = 24;
const PACKET_HEADER_SIZE = 16;

/**
 * Swap bytes of a 16-bit value.
 * @param {number} value
 * @returns {number}
 */
function swap16(value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

/**
 * Swap bytes of a 32-bit value.
 * @param {number} value
 * @returns {number}
 */
function swap32(value) {
    return (((value & 0xFF000000) >>> 24) |
            ((value & 0x00FF0000) >>> 8)  |
            ((value & 0x0000FF00) << 8)   |
            ((value & 0x000000FF) << 24)) >>> 0;
}

/**
 * Read a PCAP file from disk and return the raw Buffer.
 * @param {string} filePath  Path to the .pcap file.
 * @returns {Buffer}
 */
function openPcap(filePath) {
    return fs.readFileSync(filePath);
}

/**
 * Read the PCAP global header from bytes 0–23 of the buffer.
 *
 * Mirrors PcapReader::open() – detects native vs swapped magic,
 * byte-swaps version/snaplen/network when necessary.
 *
 * @param {Buffer} buf  The full PCAP file buffer.
 * @returns {{ magicNumber: number, versionMajor: number, versionMinor: number,
 *             snaplen: number, network: number, needsByteSwap: boolean }}
 */
function readGlobalHeader(buf) {
    if (buf.length < GLOBAL_HEADER_SIZE) {
        throw new Error('Error: Could not read PCAP global header');
    }

    // Byte 0-3: magic number (always read as LE first, then decide)
    const magicNumber = buf.readUInt32LE(0);

    let versionMajor = buf.readUInt16LE(4);
    let versionMinor = buf.readUInt16LE(6);
    // thiszone (int32) at offset 8, sigfigs (uint32) at offset 12 – not needed
    let snaplen      = buf.readUInt32LE(16);
    let network      = buf.readUInt32LE(20);

    let needsByteSwap = false;

    if (magicNumber === PCAP_MAGIC_NATIVE) {
        needsByteSwap = false;
    } else if (magicNumber === PCAP_MAGIC_SWAPPED) {
        needsByteSwap = true;
        // The fields we already read as LE need to be byte-swapped
        versionMajor = swap16(versionMajor);
        versionMinor = swap16(versionMinor);
        snaplen      = swap32(snaplen);
        network      = swap32(network);
    } else {
        throw new Error(
            `Error: Invalid PCAP magic number: 0x${magicNumber.toString(16)}`
        );
    }

    console.log(`Opened PCAP file`);
    console.log(`  Version: ${versionMajor}.${versionMinor}`);
    console.log(`  Snaplen: ${snaplen} bytes`);
    console.log(`  Link type: ${network}${network === 1 ? ' (Ethernet)' : ''}`);

    return { magicNumber, versionMajor, versionMinor, snaplen, network, needsByteSwap };
}

/**
 * Generator that yields every packet in the PCAP buffer.
 *
 * Starts at offset 24 (right after the global header). For each packet
 * it reads the 16-byte packet header, then slices out `inclLen` bytes
 * of packet data – exactly mirroring PcapReader::readNextPacket().
 *
 * @param {Buffer} buf  The full PCAP file buffer.
 * @yields {{ tsSec: number, tsUsec: number, inclLen: number,
 *            origLen: number, data: Buffer }}
 */
function* readPackets(buf) {
    // We need the global header to know snaplen and byte-swap flag
    const header = readGlobalHeader_internal(buf);

    let offset = GLOBAL_HEADER_SIZE;

    while (offset + PACKET_HEADER_SIZE <= buf.length) {
        // Read packet header fields (PCAP stores these in the file's
        // native byte order, which we detected from the magic number)
        let tsSec   = buf.readUInt32LE(offset);
        let tsUsec  = buf.readUInt32LE(offset + 4);
        let inclLen = buf.readUInt32LE(offset + 8);
        let origLen = buf.readUInt32LE(offset + 12);

        // Swap bytes if the file was written in big-endian
        if (header.needsByteSwap) {
            tsSec   = swap32(tsSec);
            tsUsec  = swap32(tsUsec);
            inclLen = swap32(inclLen);
            origLen = swap32(origLen);
        }

        // Sanity check on packet length
        if (inclLen > header.snaplen || inclLen > 65535) {
            console.error(`Error: Invalid packet length: ${inclLen}`);
            return;
        }

        offset += PACKET_HEADER_SIZE;

        if (offset + inclLen > buf.length) {
            console.error('Error: Could not read packet data');
            return;
        }

        // Slice out the packet data
        const data = buf.subarray(offset, offset + inclLen);
        offset += inclLen;

        yield { tsSec, tsUsec, inclLen, origLen, data };
    }
}

/**
 * Internal helper – parses the global header without console output.
 * Used by readPackets() so it can determine needsByteSwap and snaplen
 * without duplicating logic.
 * @param {Buffer} buf
 * @returns {{ snaplen: number, needsByteSwap: boolean }}
 */
function readGlobalHeader_internal(buf) {
    if (buf.length < GLOBAL_HEADER_SIZE) {
        throw new Error('Error: Could not read PCAP global header');
    }

    const magicNumber = buf.readUInt32LE(0);
    let snaplen       = buf.readUInt32LE(16);
    let needsByteSwap = false;

    if (magicNumber === PCAP_MAGIC_NATIVE) {
        needsByteSwap = false;
    } else if (magicNumber === PCAP_MAGIC_SWAPPED) {
        needsByteSwap = true;
        snaplen = swap32(snaplen);
    } else {
        throw new Error(
            `Error: Invalid PCAP magic number: 0x${magicNumber.toString(16)}`
        );
    }

    return { snaplen, needsByteSwap };
}

// ============================================================================
// Exports
// ============================================================================
module.exports = {
    openPcap,
    readGlobalHeader,
    readPackets,
};
