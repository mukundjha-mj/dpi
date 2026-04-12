// ============================================================================
// fastPath.js - Fast Path Processor (worker thread)
// Converted from: include/fast_path.h + src/fast_path.cpp
// ============================================================================
//
// In C++ this runs as a dedicated std::thread.  In Node.js we use the
// worker_threads module:
//
//   - When this file is REQUIRED as a module (isMainThread === true),
//     it exports the FastPath class used by the parent to spawn and
//     communicate with worker threads.
//
//   - When this file is EXECUTED inside a Worker (isMainThread === false),
//     it runs the packet-processing loop, receiving packets from the
//     parent via parentPort.on('message').
//
// ============================================================================

'use strict';

const {
    isMainThread,
    parentPort,
    workerData,
    Worker,
} = require('worker_threads');

const path = require('path');

// ============================================================================
// Worker-side:  packet processing loop
// ============================================================================

if (!isMainThread && workerData !== null) {
    // ---- Imports (resolved from src directory) -------------------------
    const { extractSNI, extractHTTPHost } = require(path.join(__dirname, 'sniExtractor'));
    const { appTypeToString, sniToAppType } = require(path.join(__dirname, 'types'));
    const { RuleManager }        = require(path.join(__dirname, 'ruleManager'));
    const { ConnectionTracker }  = require(path.join(__dirname, 'connectionTracker'));

    // ---- State ------------------------------------------------------------
    const tracker = new ConnectionTracker();
    const rules   = new RuleManager();

    // Hydrate blocking rules from the config passed via workerData
    const cfg = workerData.ruleManagerConfig || {};
    if (Array.isArray(cfg.ips))     cfg.ips.forEach(ip  => rules.addBlockedIP(ip));
    if (Array.isArray(cfg.apps))    cfg.apps.forEach(a  => rules.addBlockedApp(a));
    if (Array.isArray(cfg.domains)) cfg.domains.forEach(d => rules.addBlockedDomain(d));

    const fpId = workerData.id ?? 0;

    // Stats
    let packetsProcessed = 0;
    let packetsForwarded = 0;
    let packetsDropped   = 0;
    let sniExtractions   = 0;

    // ---- Message handler --------------------------------------------------
    parentPort.on('message', (msg) => {
        // ----- Control messages --------------------------------------------
        if (msg && msg.type === 'getStats') {
            const connStats = tracker.getStats();
            parentPort.postMessage({
                type: 'stats',
                stats: {
                    packetsProcessed,
                    packetsForwarded,
                    packetsDropped,
                    sniExtractions,
                    totalFlows:   connStats.totalFlows,
                    blockedFlows: connStats.blockedFlows,
                },
            });
            return;
        }

        if (msg && msg.type === 'shutdown') {
            process.exit(0);
        }

        // ----- Packet message ----------------------------------------------
        // Expected shape:
        //   { data: Uint8Array | number[],
        //     parsed: { srcIp, dstIp, srcPort, dstPort, protocol,
        //               hasTcp, hasUdp, payloadOffset, payloadLength,
        //               tcpFlags },
        //     fiveTupleKey: string,
        //     tsSec:  number,
        //     tsUsec: number }

        const packet = msg;
        packetsProcessed++;

        // Reconstruct Buffer from transferred data
        const dataBuf = Buffer.from(packet.data);
        const parsed  = packet.parsed;
        const key     = packet.fiveTupleKey;

        // Get or create flow (bidirectional lookup handled internally)
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
        flow.byteCount += dataBuf.length;

        // Already blocked → drop immediately
        if (flow.blocked) {
            packetsDropped++;
            parentPort.postMessage({ action: 'drop', packet });
            return;
        }

        // ---- SNI extraction (TLS Client Hello on port 443) ----------------
        if ((flow.appType === 'Unknown' || flow.appType === 'HTTPS') &&
            flow.sni === null && parsed.hasTcp && parsed.dstPort === 443) {

            if (parsed.payloadLength > 5) {
                const sni = extractSNI(
                    dataBuf.subarray(parsed.payloadOffset),
                );
                if (sni !== null) {
                    sniExtractions++;
                    flow.sni     = sni;
                    flow.appType = appTypeToString(sniToAppType(sni));
                }
            }
        }

        // ---- HTTP Host extraction (port 80) -------------------------------
        if ((flow.appType === 'Unknown' || flow.appType === 'HTTP') &&
            flow.sni === null && parsed.hasTcp && parsed.dstPort === 80) {

            if (parsed.payloadLength > 0) {
                const host = extractHTTPHost(
                    dataBuf.subarray(parsed.payloadOffset),
                );
                if (host !== null) {
                    flow.host    = host;
                    flow.sni     = host;
                    flow.appType = appTypeToString(sniToAppType(host));
                }
            }
        }

        // ---- DNS classification -------------------------------------------
        if (flow.appType === 'Unknown' &&
            (parsed.dstPort === 53 || parsed.srcPort === 53)) {
            flow.appType = 'DNS';
        }

        // ---- Port-based fallback ------------------------------------------
        if (flow.appType === 'Unknown') {
            if (parsed.dstPort === 443)      flow.appType = 'HTTPS';
            else if (parsed.dstPort === 80)  flow.appType = 'HTTP';
        }

        // ---- Blocking rules check -----------------------------------------
        const blocked = rules.isBlocked(
            parsed.srcIp,
            flow.appType,
            flow.sni || '',
        );

        if (blocked) {
            flow.blocked = true;
            tracker.markBlocked(key);
            packetsDropped++;

            let logMsg = `[FP${fpId}] BLOCKED: ${parsed.srcIp} -> ${parsed.dstIp} (${flow.appType}`;
            if (flow.sni) logMsg += `: ${flow.sni}`;
            logMsg += ')';
            console.log(logMsg);

            parentPort.postMessage({ action: 'drop', packet });
            return;
        }

        // ---- Forward ------------------------------------------------------
        packetsForwarded++;
        parentPort.postMessage({ action: 'forward', packet });
    });
}

// ============================================================================
// Module-side:  FastPath class exported for the parent thread
// ============================================================================

class FastPath {
    /**
     * @param {number} id                  Worker / FP identifier.
     * @param {object} ruleManagerConfig   { ips: string[], apps: string[], domains: string[] }
     */
    constructor(id, ruleManagerConfig) {
        this._id     = id;
        this._config = ruleManagerConfig || { ips: [], apps: [], domains: [] };
        this._worker = null;
        this._resultCallback = null;
    }

    // ========== Lifecycle ==================================================

    /**
     * Spawn this file as a Worker thread.
     */
    start() {
        this._worker = new Worker(__filename, {
            workerData: {
                id: this._id,
                ruleManagerConfig: this._config,
            },
        });

        // Forward worker messages to the registered callback
        this._worker.on('message', (msg) => {
            if (this._resultCallback) {
                this._resultCallback(msg);
            }
        });

        this._worker.on('error', (err) => {
            console.error(`[FastPath ${this._id}] Worker error:`, err);
        });

        this._worker.on('exit', (code) => {
            if (code !== 0) {
                console.error(`[FastPath ${this._id}] Worker exited with code ${code}`);
            }
        });

        console.log(`[FP${this._id}] Started`);
    }

    /**
     * Send a packet object to the worker for processing.
     * @param {object} packetObj  { data, parsed, fiveTupleKey, tsSec, tsUsec }
     */
    send(packetObj) {
        if (this._worker) {
            this._worker.postMessage(packetObj);
        }
    }

    /**
     * Register a callback for messages coming back from the worker.
     * @param {function} callback  (msg) => void
     */
    onResult(callback) {
        this._resultCallback = callback;
    }

    /**
     * Gracefully terminate the worker thread.
     */
    terminate() {
        if (this._worker) {
            this._worker.postMessage({ type: 'shutdown' });
        }
    }
}

module.exports = { FastPath };
