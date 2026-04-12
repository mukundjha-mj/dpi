// ============================================================================
// types.js - Deep Packet Inspection type definitions
// Converted from: include/types.h + src/types.cpp
// ============================================================================

'use strict';

// ============================================================================
// Application Classification
// ============================================================================
const AppType = Object.freeze({
    UNKNOWN:    0,
    HTTP:       1,
    HTTPS:      2,
    DNS:        3,
    TLS:        4,
    QUIC:       5,
    // Specific applications (detected via SNI)
    GOOGLE:     6,
    FACEBOOK:   7,
    YOUTUBE:    8,
    TWITTER:    9,
    INSTAGRAM:  10,
    NETFLIX:    11,
    AMAZON:     12,
    MICROSOFT:  13,
    APPLE:      14,
    WHATSAPP:   15,
    TELEGRAM:   16,
    TIKTOK:     17,
    SPOTIFY:    18,
    ZOOM:       19,
    DISCORD:    20,
    GITHUB:     21,
    CLOUDFLARE: 22,
    // Keep this last for counting
    APP_COUNT:  23,
});

// ============================================================================
// Connection State
// ============================================================================
const ConnectionState = Object.freeze({
    NEW:         0,
    ESTABLISHED: 1,
    CLASSIFIED:  2,
    BLOCKED:     3,
    CLOSED:      4,
});

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================
const PacketAction = Object.freeze({
    FORWARD:  0,  // Send to internet
    DROP:     1,  // Block/drop the packet
    INSPECT:  2,  // Needs further inspection
    LOG_ONLY: 3,  // Forward but log
});

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================

/**
 * Create a FiveTuple object.
 * @param {number} srcIp
 * @param {number} dstIp
 * @param {number} srcPort
 * @param {number} dstPort
 * @param {number} protocol  TCP=6, UDP=17
 * @returns {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }}
 */
function createFiveTuple(srcIp, dstIp, srcPort, dstPort, protocol) {
    return { srcIp, dstIp, srcPort, dstPort, protocol };
}

/**
 * Format an IP stored as a 32-bit integer (little-endian byte order
 * as stored by the original C++ code) into a dotted-decimal string.
 * @param {number} ip
 * @returns {string}
 */
function formatIP(ip) {
    return `${(ip >>> 0) & 0xFF}.${(ip >>> 8) & 0xFF}.${(ip >>> 16) & 0xFF}.${(ip >>> 24) & 0xFF}`;
}

/**
 * Produce a human-readable string for a FiveTuple.
 * @param {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }} tuple
 * @returns {string}
 */
function fiveTupleToString(tuple) {
    const proto = tuple.protocol === 6 ? 'TCP' : tuple.protocol === 17 ? 'UDP' : '?';
    return `${formatIP(tuple.srcIp)}:${tuple.srcPort} -> ${formatIP(tuple.dstIp)}:${tuple.dstPort} (${proto})`;
}

/**
 * Create the reverse (bidirectional) tuple.
 * @param {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }} tuple
 * @returns {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }}
 */
function reverseFiveTuple(tuple) {
    return createFiveTuple(tuple.dstIp, tuple.srcIp, tuple.dstPort, tuple.srcPort, tuple.protocol);
}

/**
 * Deterministic string key for a FiveTuple (used as Map key).
 * Mirrors the C++ FiveTupleHash behaviour.
 * @param {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }} tuple
 * @returns {string}
 */
function fiveTupleKey(tuple) {
    return `${tuple.srcIp}:${tuple.dstIp}:${tuple.srcPort}:${tuple.dstPort}:${tuple.protocol}`;
}

/**
 * Check equality of two FiveTuple objects.
 */
function fiveTupleEquals(a, b) {
    return a.srcIp === b.srcIp &&
           a.dstIp === b.dstIp &&
           a.srcPort === b.srcPort &&
           a.dstPort === b.dstPort &&
           a.protocol === b.protocol;
}

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================

/**
 * Create a Connection object.
 * @param {{ srcIp:number, dstIp:number, srcPort:number, dstPort:number, protocol:number }} tuple
 * @returns {object}
 */
function createConnection(tuple) {
    return {
        tuple,
        state:      ConnectionState.NEW,
        appType:    AppType.UNKNOWN,
        sni:        '',
        packetsIn:  0,
        packetsOut: 0,
        bytesIn:    0,
        bytesOut:   0,
        firstSeen:  Date.now(),
        lastSeen:   Date.now(),
        action:     PacketAction.FORWARD,
        synSeen:    false,
        synAckSeen: false,
        finSeen:    false,
    };
}

// ============================================================================
// Packet wrapper for queue passing
// ============================================================================

/**
 * Create a PacketJob object.
 * @param {object} opts
 * @returns {object}
 */
function createPacketJob(opts = {}) {
    return {
        packetId:       opts.packetId       || 0,
        tuple:          opts.tuple          || createFiveTuple(0, 0, 0, 0, 0),
        data:           opts.data           || Buffer.alloc(0),
        ethOffset:      opts.ethOffset      || 0,
        ipOffset:       opts.ipOffset       || 0,
        transportOffset:opts.transportOffset|| 0,
        payloadOffset:  opts.payloadOffset  || 0,
        payloadLength:  opts.payloadLength  || 0,
        tcpFlags:       opts.tcpFlags       || 0,
        tsSec:          opts.tsSec          || 0,
        tsUsec:         opts.tsUsec         || 0,
    };
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Create a DPIStats object (plain counters – single-threaded in JS).
 * @returns {object}
 */
function createDPIStats() {
    return {
        totalPackets:     0,
        totalBytes:       0,
        forwardedPackets: 0,
        droppedPackets:   0,
        tcpPackets:       0,
        udpPackets:       0,
        otherPackets:     0,
        activeConnections:0,
    };
}

// ============================================================================
// AppType <-> String helpers
// ============================================================================

/** @type {Map<number,string>} */
const _appTypeStringMap = new Map([
    [AppType.UNKNOWN,    'Unknown'],
    [AppType.HTTP,       'HTTP'],
    [AppType.HTTPS,      'HTTPS'],
    [AppType.DNS,        'DNS'],
    [AppType.TLS,        'TLS'],
    [AppType.QUIC,       'QUIC'],
    [AppType.GOOGLE,     'Google'],
    [AppType.FACEBOOK,   'Facebook'],
    [AppType.YOUTUBE,    'YouTube'],
    [AppType.TWITTER,    'Twitter/X'],
    [AppType.INSTAGRAM,  'Instagram'],
    [AppType.NETFLIX,    'Netflix'],
    [AppType.AMAZON,     'Amazon'],
    [AppType.MICROSOFT,  'Microsoft'],
    [AppType.APPLE,      'Apple'],
    [AppType.WHATSAPP,   'WhatsApp'],
    [AppType.TELEGRAM,   'Telegram'],
    [AppType.TIKTOK,     'TikTok'],
    [AppType.SPOTIFY,    'Spotify'],
    [AppType.ZOOM,       'Zoom'],
    [AppType.DISCORD,    'Discord'],
    [AppType.GITHUB,     'GitHub'],
    [AppType.CLOUDFLARE, 'Cloudflare'],
]);

/**
 * Convert an AppType value to its display string.
 * @param {number} type
 * @returns {string}
 */
function appTypeToString(type) {
    return _appTypeStringMap.get(type) || 'Unknown';
}

/**
 * Map an SNI / domain string to an AppType value.
 * @param {string} sni
 * @returns {number}
 */
function sniToAppType(sni) {
    if (!sni) return AppType.UNKNOWN;

    const lower = sni.toLowerCase();

    // Google (including YouTube-adjacent CDN domains)
    if (lower.includes('google') || lower.includes('gstatic') ||
        lower.includes('googleapis') || lower.includes('ggpht') ||
        lower.includes('gvt1')) {
        return AppType.GOOGLE;
    }

    // YouTube
    if (lower.includes('youtube') || lower.includes('ytimg') ||
        lower.includes('youtu.be') || lower.includes('yt3.ggpht')) {
        return AppType.YOUTUBE;
    }

    // Facebook / Meta
    if (lower.includes('facebook') || lower.includes('fbcdn') ||
        lower.includes('fb.com') || lower.includes('fbsbx') ||
        lower.includes('meta.com')) {
        return AppType.FACEBOOK;
    }

    // Instagram
    if (lower.includes('instagram') || lower.includes('cdninstagram')) {
        return AppType.INSTAGRAM;
    }

    // WhatsApp
    if (lower.includes('whatsapp') || lower.includes('wa.me')) {
        return AppType.WHATSAPP;
    }

    // Netflix  (must be checked BEFORE Twitter — "netflix.com" contains "x.com")
    if (lower.includes('netflix') || lower.includes('nflxvideo') ||
        lower.includes('nflximg')) {
        return AppType.NETFLIX;
    }

    // Microsoft  (must be checked BEFORE Twitter — "microsoft.com" contains "t.co")
    if (lower.includes('microsoft') || lower.includes('msn.com') ||
        lower.includes('office') || lower.includes('azure') ||
        lower.includes('live.com') || lower.includes('outlook') ||
        lower.includes('bing')) {
        return AppType.MICROSOFT;
    }

    // Twitter / X
    if (lower.includes('twitter') || lower.includes('twimg') ||
        lower.includes('x.com') || lower.includes('t.co')) {
        return AppType.TWITTER;
    }

    // Amazon
    if (lower.includes('amazon') || lower.includes('amazonaws') ||
        lower.includes('cloudfront') || lower.includes('aws')) {
        return AppType.AMAZON;
    }

    // Apple
    if (lower.includes('apple') || lower.includes('icloud') ||
        lower.includes('mzstatic') || lower.includes('itunes')) {
        return AppType.APPLE;
    }

    // Telegram
    if (lower.includes('telegram') || lower.includes('t.me')) {
        return AppType.TELEGRAM;
    }

    // TikTok
    if (lower.includes('tiktok') || lower.includes('tiktokcdn') ||
        lower.includes('musical.ly') || lower.includes('bytedance')) {
        return AppType.TIKTOK;
    }

    // Spotify
    if (lower.includes('spotify') || lower.includes('scdn.co')) {
        return AppType.SPOTIFY;
    }

    // Zoom
    if (lower.includes('zoom')) {
        return AppType.ZOOM;
    }

    // Discord
    if (lower.includes('discord') || lower.includes('discordapp')) {
        return AppType.DISCORD;
    }

    // GitHub
    if (lower.includes('github') || lower.includes('githubusercontent')) {
        return AppType.GITHUB;
    }

    // Cloudflare
    if (lower.includes('cloudflare') || lower.includes('cf-')) {
        return AppType.CLOUDFLARE;
    }

    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType.HTTPS;
}

// ============================================================================
// Exports
// ============================================================================
module.exports = {
    AppType,
    ConnectionState,
    PacketAction,
    createFiveTuple,
    formatIP,
    fiveTupleToString,
    reverseFiveTuple,
    fiveTupleKey,
    fiveTupleEquals,
    createConnection,
    createPacketJob,
    createDPIStats,
    appTypeToString,
    sniToAppType,
};
