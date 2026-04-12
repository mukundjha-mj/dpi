// ============================================================================
// index.js - DPI Engine entry point
// Converted from: src/main_working.cpp
// ============================================================================

'use strict';

const fs   = require('fs');
const path = require('path');

const { openPcap, readGlobalHeader, readPackets } = require('./pcapReader');
const { parsePacket }                             = require('./packetParser');
const { extractSNI, extractHTTPHost }             = require('./sniExtractor');
const { AppType, appTypeToString, sniToAppType }  = require('./types');
const { RuleManager }                             = require('./ruleManager');
const { ConnectionTracker }                       = require('./connectionTracker');

// ============================================================================
// Flow key helpers
// ============================================================================

/**
 * Build the canonical flow key string.
 * Format: srcIp:srcPort-dstIp:dstPort-protocol
 */
function flowKey(srcIp, srcPort, dstIp, dstPort, protocol) {
    return `${srcIp}:${srcPort}-${dstIp}:${dstPort}-${protocol}`;
}


// ============================================================================
// Usage / Help
// ============================================================================

function printUsage(prog) {
    console.log(`
DPI Engine - Deep Packet Inspection System (JavaScript)
=======================================================

Usage: node ${prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  node ${prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
`);
}

// ============================================================================
// Main
// ============================================================================

function main() {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        printUsage(path.basename(process.argv[1]));
        process.exit(1);
    }

    const inputFile  = args[0];
    const outputFile = args[1];

    const rules = new RuleManager();

    // Parse command-line options
    for (let i = 2; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--block-ip' && i + 1 < args.length) {
            rules.addBlockedIP(args[++i]);
        } else if (arg === '--block-app' && i + 1 < args.length) {
            rules.addBlockedApp(args[++i]);
        } else if (arg === '--block-domain' && i + 1 < args.length) {
            rules.addBlockedDomain(args[++i]);
        }
    }

    console.log('');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    DPI ENGINE v1.0 (JS)                     ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');

    // Open and read the PCAP file
    let pcapBuf;
    try {
        pcapBuf = openPcap(inputFile);
    } catch (err) {
        console.error(`Error: Could not open file: ${inputFile}`);
        process.exit(1);
    }

    const ghdr = readGlobalHeader(pcapBuf);

    // Prepare output: collect chunks, write at end
    const outputChunks = [];

    // Write the original 24-byte global header verbatim to output
    outputChunks.push(pcapBuf.subarray(0, 24));

    // Connection tracker (flow table with bidirectional lookup)
    const tracker = new ConnectionTracker();

    // Statistics
    let totalPackets = 0;
    let totalBytes   = 0;
    let tcpCount     = 0;
    let udpCount     = 0;
    let forwarded    = 0;
    let dropped      = 0;
    /** @type {Map<number, number>}  AppType -> packet count */
    const appStats = new Map();

    console.log('[DPI] Processing packets...');

    for (const pkt of readPackets(pcapBuf)) {
        totalPackets++;
        totalBytes += pkt.data.length;

        // Parse the Ethernet frame
        const parsed = parsePacket(pkt.data);
        if (parsed === null) continue;
        if (!parsed.hasTcp && !parsed.hasUdp) continue;

        // Count by protocol
        if (parsed.hasTcp) tcpCount++;
        if (parsed.hasUdp) udpCount++;

        // Build flow key; getOrCreateFlow handles bidirectional lookup
        const key  = flowKey(parsed.srcIp, parsed.srcPort, parsed.dstIp, parsed.dstPort, parsed.protocol);
        const flow = tracker.getOrCreateFlow(key);

        // Populate addressing fields on first packet of the flow
        if (flow.packetCount === 0) {
            flow.srcIp    = parsed.srcIp;
            flow.dstIp    = parsed.dstIp;
            flow.srcPort  = parsed.srcPort;
            flow.dstPort  = parsed.dstPort;
            flow.protocol = parsed.protocol;
        }

        flow.packetCount++;
        flow.byteCount += pkt.data.length;

        // ----- SNI extraction (TLS Client Hello on port 443) -----
        if ((flow.appType === 'Unknown' || flow.appType === 'HTTPS') &&
            flow.sni === null && parsed.hasTcp && parsed.dstPort === 443) {

            if (parsed.payloadLength > 5) {
                const sni = extractSNI(
                    pkt.data.subarray(parsed.payloadOffset),
                );
                if (sni !== null) {
                    flow.sni     = sni;
                    flow.appType = appTypeToString(sniToAppType(sni));
                }
            }
        }

        // ----- HTTP Host extraction (port 80) -----
        if ((flow.appType === 'Unknown' || flow.appType === 'HTTP') &&
            flow.sni === null && parsed.hasTcp && parsed.dstPort === 80) {

            if (parsed.payloadLength > 0) {
                const host = extractHTTPHost(
                    pkt.data.subarray(parsed.payloadOffset),
                );
                if (host !== null) {
                    flow.sni     = host;
                    flow.appType = appTypeToString(sniToAppType(host));
                }
            }
        }

        // DNS classification
        if (flow.appType === 'Unknown' &&
            (parsed.dstPort === 53 || parsed.srcPort === 53)) {
            flow.appType = 'DNS';
        }

        // Port-based fallback
        if (flow.appType === 'Unknown') {
            if (parsed.dstPort === 443)      flow.appType = 'HTTPS';
            else if (parsed.dstPort === 80)  flow.appType = 'HTTP';
        }

        // ----- Blocking rules -----
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(parsed.srcIp, flow.appType, flow.sni || '');
            if (flow.blocked) {
                let msg = `[BLOCKED] ${parsed.srcIp} -> ${parsed.dstIp} (${flow.appType}`;
                if (flow.sni) msg += `: ${flow.sni}`;
                msg += ')';
                console.log(msg);
            }
        }

        // Update per-app stats
        appStats.set(flow.appType, (appStats.get(flow.appType) || 0) + 1);

        // Forward or drop
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            // Write packet header (16 bytes) + data to output
            const pktHdrBuf = Buffer.alloc(16);
            pktHdrBuf.writeUInt32LE(pkt.tsSec, 0);
            pktHdrBuf.writeUInt32LE(pkt.tsUsec, 4);
            pktHdrBuf.writeUInt32LE(pkt.data.length, 8);
            pktHdrBuf.writeUInt32LE(pkt.data.length, 12);
            outputChunks.push(pktHdrBuf);
            outputChunks.push(Buffer.from(pkt.data));
        }
    }

    // Write the output PCAP file
    fs.writeFileSync(outputFile, Buffer.concat(outputChunks));

    // ====================================================================
    // Print processing report
    // ====================================================================
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                      PROCESSING REPORT                       ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log(`║ Total Packets:      ${String(totalPackets).padStart(10)}                             ║`);
    console.log(`║ Total Bytes:        ${String(totalBytes).padStart(10)}                             ║`);
    console.log(`║ TCP Packets:        ${String(tcpCount).padStart(10)}                             ║`);
    console.log(`║ UDP Packets:        ${String(udpCount).padStart(10)}                             ║`);
    console.log(`║ Forwarded:          ${String(forwarded).padStart(10)}                             ║`);
    console.log(`║ Dropped:            ${String(dropped).padStart(10)}                             ║`);

    const trackerStats = tracker.getStats();
    console.log(`║ Active Flows:       ${String(trackerStats.totalFlows).padStart(10)}                             ║`);
    console.log(`║ Blocked Flows:      ${String(trackerStats.blockedFlows).padStart(10)}                             ║`);
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║                    APPLICATION BREAKDOWN                     ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');

    // Sort apps by packet count descending
    const sortedApps = [...appStats.entries()].sort((a, b) => b[1] - a[1]);

    for (const [app, count] of sortedApps) {
        const pct    = totalPackets > 0 ? (100.0 * count / totalPackets) : 0;
        const barLen = Math.floor(pct / 5);
        const bar    = '#'.repeat(barLen);

        const appName  = String(app).padEnd(15);
        const countStr = String(count).padStart(8);
        const pctStr   = pct.toFixed(1).padStart(5);
        const barStr   = bar.padEnd(20);

        console.log(`║ ${appName}${countStr} ${pctStr}% ${barStr}  ║`);
    }

    console.log('╚══════════════════════════════════════════════════════════════╝');

    // List all unique SNIs detected
    console.log('');
    console.log('[Detected Applications/Domains]');
    /** @type {Map<string, string>} */
    const uniqueSNIs = new Map();
    for (const flow of tracker.getAllFlows().values()) {
        if (flow.sni) {
            uniqueSNIs.set(flow.sni, flow.appType);
        }
    }
    for (const [sni, app] of uniqueSNIs) {
        console.log(`  - ${sni} -> ${app}`);
    }

    console.log('');
    console.log(`Output written to: ${outputFile}`);
}

// ============================================================================
// Run
// ============================================================================
main();
