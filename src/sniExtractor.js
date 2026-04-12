// ============================================================================
// sniExtractor.js - Extract SNI from TLS Client Hello, Host from HTTP requests
// Converted from: include/sni_extractor.h + src/sni_extractor.cpp
// ============================================================================

'use strict';

// ============================================================================
// TLS SNI Extractor
// ============================================================================

/**
 * Extract the Server Name Indication (SNI) hostname from a TLS Client Hello.
 *
 * @param {Buffer} payload  TCP payload bytes starting from the TLS record.
 * @returns {string|null}   The hostname, or null if not found / not a Client Hello.
 */
function extractSNI(payload) {
    const len = payload.length;

    // Need at least 5 bytes for the TLS record header
    if (len < 5) return null;

    // Byte 0: Content Type — 0x16 = Handshake
    if (payload[0] !== 0x16) return null;

    // Byte 5: Handshake Type — 0x01 = Client Hello
    if (len < 6) return null;
    if (payload[5] !== 0x01) return null;

    // ---------------------------------------------------------------
    // Offsets within the Client Hello, counted from the start of the
    // TLS record:
    //   0      Content Type          (1 byte)
    //   1-2    TLS Version           (2 bytes)
    //   3-4    Record Length          (2 bytes)
    //   5      Handshake Type         (1 byte)
    //   6-8    Handshake Length       (3 bytes)
    //   9-10   Client Version         (2 bytes)
    //  11-42   Random                 (32 bytes)
    //  43      Session ID Length       (1 byte)
    // ---------------------------------------------------------------

    // Skip to Session ID Length at offset 43
    let offset = 43;
    if (offset >= len) return null;

    // Session ID
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;

    // Cipher Suites
    if (offset + 2 > len) return null;
    const cipherSuitesLen = payload.readUInt16BE(offset);
    offset += 2 + cipherSuitesLen;

    // Compression Methods
    if (offset >= len) return null;
    const compressionMethodsLen = payload[offset];
    offset += 1 + compressionMethodsLen;

    // Extensions
    if (offset + 2 > len) return null;
    const extensionsLen = payload.readUInt16BE(offset);
    offset += 2;

    let extensionsEnd = offset + extensionsLen;
    if (extensionsEnd > len) {
        extensionsEnd = len; // Truncated, but try to parse anyway
    }

    // Walk through extensions looking for SNI (type 0x0000)
    while (offset + 4 <= extensionsEnd) {
        const extType = payload.readUInt16BE(offset);
        const extLen  = payload.readUInt16BE(offset + 2);
        offset += 4;

        if (offset + extLen > extensionsEnd) break;

        if (extType === 0x0000) {
            // SNI extension found
            // Structure:
            //   SNI List Length  (2 bytes)
            //   SNI Type         (1 byte) — 0x00 = hostname
            //   SNI Name Length  (2 bytes)
            //   SNI Name         (variable)
            if (extLen < 5) break;

            // Skip SNI list length (2 bytes)
            const sniType     = payload[offset + 2];
            const sniNameLen  = payload.readUInt16BE(offset + 3);

            if (sniType !== 0x00) break;
            if (sniNameLen > extLen - 5) break;

            // Extract the hostname
            return payload.toString('utf8', offset + 5, offset + 5 + sniNameLen);
        }

        offset += extLen;
    }

    return null;
}

// ============================================================================
// HTTP Host Header Extractor
// ============================================================================

/** Known HTTP request method prefixes. */
const HTTP_METHODS = ['GET ', 'POST', 'PUT ', 'DELE', 'HEAD'];

/**
 * Extract the Host header value from an HTTP request payload.
 *
 * @param {Buffer} payload  TCP payload bytes containing the HTTP request.
 * @returns {string|null}   The host string, or null if not found / not HTTP.
 */
function extractHTTPHost(payload) {
    const len = payload.length;
    if (len < 4) return null;

    // Verify this looks like an HTTP request
    const prefix = payload.toString('ascii', 0, 4);
    let isHTTP = false;
    for (const method of HTTP_METHODS) {
        if (prefix === method) {
            isHTTP = true;
            break;
        }
    }
    if (!isHTTP) return null;

    // Search for "Host: " in the payload
    const hostMarker = 'Host: ';
    const hostMarkerLen = hostMarker.length; // 6

    for (let i = 0; i + hostMarkerLen < len; i++) {
        // Case-insensitive match on "Host:" (matching C++ logic)
        if ((payload[i]     === 0x48 || payload[i]     === 0x68) &&  // H or h
            (payload[i + 1] === 0x6F || payload[i + 1] === 0x4F) &&  // o or O
            (payload[i + 2] === 0x73 || payload[i + 2] === 0x53) &&  // s or S
            (payload[i + 3] === 0x74 || payload[i + 3] === 0x54) &&  // t or T
            payload[i + 4] === 0x3A) {                                // :

            // Skip "Host:" and any whitespace
            let start = i + 5;
            while (start < len && (payload[start] === 0x20 || payload[start] === 0x09)) {
                start++;
            }

            // Find end of line (\r or \n)
            let end = start;
            while (end < len && payload[end] !== 0x0D && payload[end] !== 0x0A) {
                end++;
            }

            if (end > start) {
                let host = payload.toString('ascii', start, end);

                // Remove port if present (matching C++ logic)
                const colonPos = host.indexOf(':');
                if (colonPos !== -1) {
                    host = host.substring(0, colonPos);
                }

                return host;
            }
        }
    }

    return null;
}

// ============================================================================
// Exports
// ============================================================================
module.exports = { extractSNI, extractHTTPHost };
