// ============================================================================
// connectionTracker.js - Maintains flow table for all active connections
// Converted from: include/connection_tracker.h + src/connection_tracker.cpp
// ============================================================================
//
// Features:
// - Track flows by five-tuple key (srcIp:srcPort-dstIp:dstPort-protocol)
// - Bidirectional lookup (forward key and reversed key)
// - Store classification results (appType, SNI, host)
// - Maintain per-flow statistics (packet count, byte count)
// - Mark flows as blocked
//
// ============================================================================

'use strict';

/**
 * Reverse a five-tuple key string.
 *
 * Input format:  srcIp:srcPort-dstIp:dstPort-protocol
 * Output format: dstIp:dstPort-srcIp:srcPort-protocol
 *
 * @param {string} key
 * @returns {string}
 */
function reverseKey(key) {
    // key = "srcIp:srcPort-dstIp:dstPort-protocol"
    const firstDash = key.indexOf('-');
    const lastDash  = key.lastIndexOf('-');

    const src      = key.substring(0, firstDash);          // "srcIp:srcPort"
    const dst      = key.substring(firstDash + 1, lastDash); // "dstIp:dstPort"
    const protocol = key.substring(lastDash + 1);          // "protocol"

    return `${dst}-${src}-${protocol}`;
}

/**
 * Create a fresh flow object with default field values.
 * @returns {object}
 */
function createFlow() {
    return {
        sni:         null,
        host:        null,
        appType:     'Unknown',
        blocked:     false,
        packetCount: 0,
        byteCount:   0,
        srcIp:       '',
        dstIp:       '',
        srcPort:     0,
        dstPort:     0,
        protocol:    0,
    };
}

// ============================================================================
// ConnectionTracker class
// ============================================================================

class ConnectionTracker {
    constructor() {
        /** @type {Map<string, object>} five-tuple key → flow object */
        this.flows = new Map();
    }

    // ========== Core lookup =================================================

    /**
     * Look up a flow by its five-tuple key.  If neither the forward key
     * nor the reversed key exists, create a new flow under the forward key.
     *
     * Mirrors the C++ getOrCreateConnection + bidirectional getConnection
     * logic: the forward key is checked first, then the reverse.
     *
     * @param {string} fiveTupleKey  Format: srcIp:srcPort-dstIp:dstPort-protocol
     * @returns {object}  The flow object (existing or newly created).
     */
    getOrCreateFlow(fiveTupleKey) {
        // 1. Check forward key
        if (this.flows.has(fiveTupleKey)) {
            return this.flows.get(fiveTupleKey);
        }

        // 2. Check reversed key (bidirectional matching)
        const rev = reverseKey(fiveTupleKey);
        if (this.flows.has(rev)) {
            return this.flows.get(rev);
        }

        // 3. Create new flow under the forward key
        const flow = createFlow();
        this.flows.set(fiveTupleKey, flow);
        return flow;
    }

    /**
     * Look up an existing flow.  Returns null if neither the forward key
     * nor the reversed key is found.
     *
     * @param {string} fiveTupleKey
     * @returns {object|null}
     */
    getFlow(fiveTupleKey) {
        if (this.flows.has(fiveTupleKey)) {
            return this.flows.get(fiveTupleKey);
        }

        const rev = reverseKey(fiveTupleKey);
        if (this.flows.has(rev)) {
            return this.flows.get(rev);
        }

        return null;
    }

    // ========== Blocking ====================================================

    /**
     * Mark a flow as blocked.
     * No-op if the flow does not exist.
     *
     * @param {string} fiveTupleKey
     */
    markBlocked(fiveTupleKey) {
        const flow = this.getFlow(fiveTupleKey);
        if (flow) {
            flow.blocked = true;
        }
    }

    /**
     * Check whether a flow is blocked.
     * Returns false if the flow is not found.
     *
     * @param {string} fiveTupleKey
     * @returns {boolean}
     */
    isBlocked(fiveTupleKey) {
        const flow = this.getFlow(fiveTupleKey);
        return flow ? flow.blocked : false;
    }

    // ========== Statistics / inspection =====================================

    /**
     * Aggregate statistics over all tracked flows.
     *
     * @returns {{ totalFlows: number, blockedFlows: number }}
     */
    getStats() {
        let blockedFlows = 0;
        for (const flow of this.flows.values()) {
            if (flow.blocked) blockedFlows++;
        }
        return {
            totalFlows:   this.flows.size,
            blockedFlows,
        };
    }

    /**
     * Return the underlying flows Map (for iteration / reporting).
     *
     * @returns {Map<string, object>}
     */
    getAllFlows() {
        return this.flows;
    }
}

module.exports = { ConnectionTracker };
