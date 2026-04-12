// ============================================================================
// loadBalancer.js - Distributes packets across FastPath workers
// Converted from: include/load_balancer.h + src/load_balancer.cpp
// ============================================================================
//
// Architecture (mirrors the C++ pipeline):
//   Reader  ->  LoadBalancer  ->  FastPath workers
//
// The LoadBalancer hashes each packet's five-tuple key (djb2) and sends it
// to the corresponding FastPath worker (hash % numFastPaths).  This ensures
// that every packet belonging to the same flow always reaches the same
// FastPath instance, which is critical for correct connection tracking and
// DPI classification.
//
// ============================================================================

'use strict';

const { FastPath } = require('./fastPath');

// ============================================================================
// djb2 string hash
// ============================================================================

/**
 * djb2 hash — a simple, fast, deterministic string hash.
 * Mirrors the C++ FiveTupleHash used in LoadBalancer::selectFP().
 *
 * @param {string} str
 * @returns {number}  Non-negative integer.
 */
function djb2Hash(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        // hash = hash * 33 + charCode
        hash = ((hash << 5) + hash) + str.charCodeAt(i);
        hash = hash | 0; // keep as 32-bit integer
    }
    return Math.abs(hash);
}

// ============================================================================
// LoadBalancer class
// ============================================================================

class LoadBalancer {
    /**
     * @param {number} id              Identifier for this LB instance.
     * @param {number} numFastPaths    Number of FastPath workers to manage.
     * @param {object} ruleManagerConfig  { ips: string[], apps: string[], domains: string[] }
     */
    constructor(id, numFastPaths, ruleManagerConfig) {
        /** LB identifier */
        this._id = id;

        /** Number of FP workers */
        this._numFastPaths = numFastPaths;

        /** Rule config passed through to each FP worker */
        this._ruleManagerConfig = ruleManagerConfig || { ips: [], apps: [], domains: [] };

        /** @type {FastPath[]} */
        this._fastPaths = [];

        /** Output callback — called with every forward/drop result */
        this._resultCallback = null;

        /** @type {number} Total packets dispatched */
        this._dispatched = 0;

        /** @type {number[]} Per-FP dispatch counts */
        this._perFpCounts = new Array(numFastPaths).fill(0);
    }

    // ========== Lifecycle ==================================================

    /**
     * Create and start all FastPath workers.
     * Each worker receives the shared rule manager config via workerData.
     */
    start() {
        for (let i = 0; i < this._numFastPaths; i++) {
            const fp = new FastPath(i, this._ruleManagerConfig);

            // Forward results from this FP to our output callback
            fp.onResult((msg) => {
                if (this._resultCallback) {
                    this._resultCallback(msg);
                }
            });

            fp.start();
            this._fastPaths.push(fp);
        }

        console.log(
            `[LB${this._id}] Started (serving FP0-FP${this._numFastPaths - 1})`,
        );
    }

    // ========== Packet distribution ========================================

    /**
     * Distribute a packet object to the appropriate FastPath worker.
     *
     * The target FP is selected by hashing the five-tuple key string
     * (djb2) and taking modulo numFastPaths — mirroring the C++
     * LoadBalancer::selectFP() which hashes the FiveTuple struct.
     *
     * @param {object} packetObj  Must contain a `fiveTupleKey` string.
     */
    distribute(packetObj) {
        const hash    = djb2Hash(packetObj.fiveTupleKey);
        const fpIndex = hash % this._numFastPaths;

        this._fastPaths[fpIndex].send(packetObj);
        this._dispatched++;
        this._perFpCounts[fpIndex]++;
    }

    // ========== Callbacks ==================================================

    /**
     * Register a callback that is invoked for every forward/drop decision
     * received from any FastPath worker.
     *
     * @param {function} callback  (msg) => void
     */
    onResult(callback) {
        this._resultCallback = callback;
    }

    // ========== Statistics ==================================================

    /**
     * Return a snapshot of this LoadBalancer's dispatch statistics.
     *
     * Mirrors the C++ LBStats struct.
     *
     * @returns {{ id: number, dispatched: number, perFpCounts: number[] }}
     */
    getStats() {
        return {
            id:          this._id,
            dispatched:  this._dispatched,
            perFpCounts: [...this._perFpCounts],
        };
    }

    // ========== Shutdown ====================================================

    /**
     * Gracefully terminate all FastPath workers.
     */
    shutdown() {
        for (const fp of this._fastPaths) {
            fp.terminate();
        }
        console.log(`[LB${this._id}] Stopped`);
    }
}

module.exports = { LoadBalancer, djb2Hash };
