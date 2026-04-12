// ============================================================================
// ruleManager.js - Manages blocking/filtering rules
// Converted from: include/rule_manager.h + src/rule_manager.cpp
// ============================================================================
//
// Rules can be:
// 1. IP-based:     Block specific source IPs
// 2. App-based:    Block specific applications (detected via SNI)
// 3. Domain-based: Block specific domains (substring match)
//
// ============================================================================

'use strict';

const { appTypeToString } = require('./types');

class RuleManager {
    constructor() {
        /** @type {Set<string>} Blocked source IPs (dotted-decimal strings) */
        this.blockedIPs = new Set();

        /** @type {Set<string>} Blocked app names (lowercase) */
        this.blockedApps = new Set();

        /** @type {Set<string>} Blocked domain substrings (lowercase) */
        this.blockedDomains = new Set();
    }

    // ========== IP Blocking ================================================

    /**
     * Add a source IP to the block list.
     * @param {string} ip  Dotted-decimal IP string, e.g. "192.168.1.50"
     */
    addBlockedIP(ip) {
        this.blockedIPs.add(ip);
        console.log(`[RuleManager] Blocked IP: ${ip}`);
    }

    // ========== Application Blocking =======================================

    /**
     * Add an application name to the block list.
     * The name is stored in lowercase for case-insensitive matching.
     * @param {string} appName  e.g. "YouTube", "Facebook"
     */
    addBlockedApp(appName) {
        this.blockedApps.add(appName.toLowerCase());
        console.log(`[RuleManager] Blocked app: ${appName}`);
    }

    // ========== Domain Blocking ============================================

    /**
     * Add a domain substring to the block list.
     * Stored in lowercase for case-insensitive matching.
     * @param {string} domain  e.g. "facebook.com"
     */
    addBlockedDomain(domain) {
        this.blockedDomains.add(domain.toLowerCase());
        console.log(`[RuleManager] Blocked domain: ${domain}`);
    }

    // ========== Combined Check =============================================

    /**
     * Check whether a flow should be blocked based on all rules.
     *
     * Mirrors the C++ RuleManager::shouldBlock() priority order:
     *   1. IP match      (most specific)
     *   2. App match
     *   3. Domain match  (substring of SNI, case-insensitive)
     *
     * @param {string} srcIp    Dotted-decimal source IP.
     * @param {string|number} appType  AppType display name (string) or
     *                                  numeric AppType value.  If a number is
     *                                  provided it is converted via
     *                                  appTypeToString() first.
     * @param {string} sni      SNI or HTTP Host string.
     * @returns {boolean}       true if the flow should be blocked.
     */
    isBlocked(srcIp, appType, sni) {
        // 1. IP check
        if (this.blockedIPs.has(srcIp)) {
            return true;
        }

        // 2. App check (compare lowercase)
        const appName = (typeof appType === 'number')
            ? appTypeToString(appType).toLowerCase()
            : String(appType).toLowerCase();

        if (this.blockedApps.has(appName)) {
            return true;
        }

        // 3. Domain substring check (case-insensitive)
        if (sni) {
            const lowerSni = sni.toLowerCase();
            for (const dom of this.blockedDomains) {
                if (lowerSni.includes(dom)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ========== Rule Inspection ============================================

    /**
     * Return a snapshot of all current rules.
     * @returns {{ ips: string[], apps: string[], domains: string[] }}
     */
    getRules() {
        return {
            ips:     [...this.blockedIPs],
            apps:    [...this.blockedApps],
            domains: [...this.blockedDomains],
        };
    }
}

module.exports = { RuleManager };
