// ============================================================================
// dpiEngine.js - Main DPI Engine orchestrator (multi-threaded pipeline)
// Converted from: include/dpi_engine.h + src/dpi_engine.cpp
// ============================================================================
//
// Architecture (mirrors the C++ pipeline):
//
//   +------------------+
//   |   PCAP Reader    |  (Reads packets from input file)
//   +--------+---------+
//            |
//            v  (djb2 hash to select LB)
//   +--------+----------+
//   |   Load Balancers  |  (numLBs instances)
//   +----+--------+-----+
//        |        |
//        v        v  (djb2 hash to select FP within LB's pool)
//   +----+--------+-----+
//   |  Fast Path Workers |  (numLBs × numFastPathsPerLB threads)
//   +----+--------+-----+
//        |        |
//        v        v
//   +----+--------+-----+
//   |   Output Collector |  (Collects forwarded packets)
//   +-------------------+
//
// ============================================================================

'use strict';

const fs   = require('fs');
const path = require('path');

const { openPcap, readGlobalHeader, readPackets } = require('./pcapReader');
const { parsePacket }                             = require('./packetParser');
const { LoadBalancer, djb2Hash }                  = require('./loadBalancer');
const { appTypeToString }                         = require('./types');

// ============================================================================
// DPIEngine class
// ============================================================================

class DPIEngine {
    /**
     * @param {object} options
     * @param {number} [options.numLBs=2]              Number of LoadBalancer instances.
     * @param {number} [options.numFastPathsPerLB=2]   FastPath workers per LB.
     * @param {string[]} [options.blockedApps=[]]       App names to block.
     * @param {string[]} [options.blockedIPs=[]]        Source IPs to block.
     * @param {string[]} [options.blockedDomains=[]]    Domain substrings to block.
     */
    constructor(options = {}) {
        this._numLBs            = options.numLBs            || 2;
        this._numFastPathsPerLB = options.numFastPathsPerLB || 2;

        this._ruleConfig = {
            ips:     options.blockedIPs     || [],
            apps:    options.blockedApps    || [],
            domains: options.blockedDomains || [],
        };

        /** @type {LoadBalancer[]} */
        this._loadBalancers = [];

        // Collected statistics
        this._totalPackets  = 0;
        this._totalBytes    = 0;
        this._tcpCount      = 0;
        this._udpCount      = 0;
        this._forwarded     = 0;
        this._dropped       = 0;
        this._resultsReceived = 0;

        // Forwarded packet buffers (for writing to output PCAP)
        /** @type {Buffer[]} */
        this._outputChunks = [];

        // Per-app packet counts
        /** @type {Map<string, number>} */
        this._appStats = new Map();

        // Unique SNIs
        /** @type {Map<string, string>} sni -> appType display string */
        this._uniqueSNIs = new Map();
    }

    // ========================================================================
    // Main entry point
    // ========================================================================

    /**
     * Process an input PCAP file, apply blocking rules via the multi-threaded
     * pipeline, and write forwarded packets to the output PCAP file.
     *
     * @param {string} inputPcapPath
     * @param {string} outputPcapPath
     */
    async start(inputPcapPath, outputPcapPath) {
        const totalFPs = this._numLBs * this._numFastPathsPerLB;

        // ---- Banner -------------------------------------------------------
        console.log('');
        console.log('╔══════════════════════════════════════════════════════════════╗');
        console.log('║                    DPI ENGINE v1.0 (JS)                     ║');
        console.log('║               Deep Packet Inspection System                 ║');
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log(`║ Configuration:                                              ║`);
        console.log(`║   Load Balancers:    ${String(this._numLBs).padStart(3)}                                    ║`);
        console.log(`║   FPs per LB:        ${String(this._numFastPathsPerLB).padStart(3)}                                    ║`);
        console.log(`║   Total FP threads:  ${String(totalFPs).padStart(3)}                                    ║`);
        console.log('╚══════════════════════════════════════════════════════════════╝');
        console.log('');

        // ---- Open PCAP ----------------------------------------------------
        console.log(`[DPIEngine] Processing: ${inputPcapPath}`);
        console.log(`[DPIEngine] Output to:  ${outputPcapPath}`);
        console.log('');

        let pcapBuf;
        try {
            pcapBuf = openPcap(inputPcapPath);
        } catch (err) {
            console.error(`[DPIEngine] Error: Cannot open input file: ${inputPcapPath}`);
            return;
        }

        const ghdr = readGlobalHeader(pcapBuf);

        // Copy the original 24-byte global header for output
        this._outputChunks.push(Buffer.from(pcapBuf.subarray(0, 24)));

        // ---- Create and start LoadBalancers --------------------------------
        for (let i = 0; i < this._numLBs; i++) {
            const lb = new LoadBalancer(i, this._numFastPathsPerLB, this._ruleConfig);
            this._loadBalancers.push(lb);
        }

        // Wrap the result collection + completion in a Promise
        let packetsSentToLBs = 0;

        const allDone = new Promise((resolve) => {
            for (const lb of this._loadBalancers) {
                lb.onResult((msg) => {
                    this._resultsReceived++;

                    if (msg.action === 'forward') {
                        this._forwarded++;

                        // Reconstruct and buffer the forwarded packet
                        const pkt = msg.packet;
                        const dataBuf = Buffer.from(pkt.data);

                        const pktHdrBuf = Buffer.alloc(16);
                        pktHdrBuf.writeUInt32LE(pkt.tsSec, 0);
                        pktHdrBuf.writeUInt32LE(pkt.tsUsec, 4);
                        pktHdrBuf.writeUInt32LE(dataBuf.length, 8);
                        pktHdrBuf.writeUInt32LE(dataBuf.length, 12);

                        this._outputChunks.push(pktHdrBuf);
                        this._outputChunks.push(dataBuf);
                    } else {
                        this._dropped++;
                    }

                    // Check if all results have been collected
                    if (this._resultsReceived >= packetsSentToLBs) {
                        resolve();
                    }
                });

                lb.start();
            }
        });

        // ---- Read packets and distribute -----------------------------------
        console.log('[Reader] Starting packet processing...');

        for (const pkt of readPackets(pcapBuf)) {
            this._totalPackets++;
            this._totalBytes += pkt.data.length;

            const parsed = parsePacket(pkt.data);
            if (parsed === null) continue;
            if (!parsed.hasTcp && !parsed.hasUdp) continue;

            if (parsed.hasTcp) this._tcpCount++;
            if (parsed.hasUdp) this._udpCount++;

            // Build five-tuple key
            const fiveTupleKey = `${parsed.srcIp}:${parsed.srcPort}-${parsed.dstIp}:${parsed.dstPort}-${parsed.protocol}`;

            // Select LB via djb2 hash
            const lbIndex = djb2Hash(fiveTupleKey) % this._numLBs;

            // Distribute to selected LB (data serialized as plain array)
            this._loadBalancers[lbIndex].distribute({
                data:          Array.from(pkt.data),
                parsed,
                fiveTupleKey,
                tsSec:         pkt.tsSec,
                tsUsec:        pkt.tsUsec,
            });

            packetsSentToLBs++;
        }

        console.log(`[Reader] Finished reading ${this._totalPackets} packets (${packetsSentToLBs} sent to LBs)`);

        // Handle edge case where no packets were sent
        if (packetsSentToLBs === 0) {
            // nothing to wait for
        } else {
            // ---- Wait for all results --------------------------------------
            await allDone;
        }

        // ---- Write output PCAP ---------------------------------------------
        fs.writeFileSync(outputPcapPath, Buffer.concat(this._outputChunks));

        // ---- Shutdown all LBs ----------------------------------------------
        for (const lb of this._loadBalancers) {
            lb.shutdown();
        }

        console.log('[DPIEngine] All threads stopped');

        // ---- Print report --------------------------------------------------
        this.printReport();

        console.log('');
        console.log(`Output written to: ${outputPcapPath}`);
    }

    // ========================================================================
    // Report
    // ========================================================================

    printReport() {
        console.log('');
        console.log('╔══════════════════════════════════════════════════════════════╗');
        console.log('║                      PROCESSING REPORT                       ║');
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log(`║ Total Packets:      ${String(this._totalPackets).padStart(10)}                             ║`);
        console.log(`║ Total Bytes:        ${String(this._totalBytes).padStart(10)}                             ║`);
        console.log(`║ TCP Packets:        ${String(this._tcpCount).padStart(10)}                             ║`);
        console.log(`║ UDP Packets:        ${String(this._udpCount).padStart(10)}                             ║`);
        console.log(`║ Forwarded:          ${String(this._forwarded).padStart(10)}                             ║`);
        console.log(`║ Dropped:            ${String(this._dropped).padStart(10)}                             ║`);

        if (this._totalPackets > 0) {
            const dropRate = (100.0 * this._dropped / this._resultsReceived).toFixed(2);
            console.log(`║ Drop Rate:          ${String(dropRate + '%').padStart(10)}                             ║`);
        }

        // LB stats
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log('║ LOAD BALANCER STATISTICS                                    ║');
        for (const lb of this._loadBalancers) {
            const stats = lb.getStats();
            console.log(`║   LB${stats.id} Dispatched:    ${String(stats.dispatched).padStart(10)}                             ║`);
        }

        console.log('╚══════════════════════════════════════════════════════════════╝');
    }
}

module.exports = { DPIEngine };
