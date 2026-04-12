// ============================================================================
// mainSimple.js - Simple single-threaded packet dumper
// Converted from: src/main_simple.cpp
// ============================================================================
//
// Usage: node mainSimple.js <pcap_file>
//
// Reads a PCAP file and prints every parsed packet's five-tuple.
// For HTTPS packets (port 443), attempts SNI extraction and prints it.
// No blocking, no output file, no multi-threading — just a diagnostic tool.
//
// ============================================================================

'use strict';

const path = require('path');

const { openPcap, readGlobalHeader, readPackets } = require('./pcapReader');
const { parsePacket }                             = require('./packetParser');
const { extractSNI }                              = require('./sniExtractor');

// ============================================================================
// Main
// ============================================================================

function main() {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.error(`Usage: node ${path.basename(process.argv[1])} <pcap_file>`);
        process.exit(1);
    }

    const inputFile = args[0];

    let pcapBuf;
    try {
        pcapBuf = openPcap(inputFile);
    } catch (err) {
        console.error(`Error: Cannot open file: ${inputFile}`);
        process.exit(1);
    }

    readGlobalHeader(pcapBuf); // validate header

    let count   = 0;
    let tlsCount = 0;

    console.log('Processing packets...');

    for (const pkt of readPackets(pcapBuf)) {
        count++;

        const parsed = parsePacket(pkt.data);
        if (parsed === null) continue;

        let line = `Packet ${count}: ` +
                   `${parsed.srcIp}:${parsed.srcPort}` +
                   ` -> ` +
                   `${parsed.dstIp}:${parsed.dstPort}`;

        // Try SNI extraction for HTTPS packets
        if (parsed.hasTcp && parsed.dstPort === 443 && parsed.payloadLength > 0) {
            const sni = extractSNI(
                pkt.data.subarray(parsed.payloadOffset),
            );
            if (sni !== null) {
                line += ` [SNI: ${sni}]`;
                tlsCount++;
            }
        }

        console.log(line);
    }

    console.log('');
    console.log(`Total packets: ${count}`);
    console.log(`SNI extracted: ${tlsCount}`);
}

main();
