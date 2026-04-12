#!/usr/bin/env node

/**
 * Generate a test PCAP file with various protocols for DPI testing.
 * Includes TLS Client Hello with SNI, HTTP, DNS, etc.
 * Node.js Equivalent of generate_test_pcap.py
 */

'use strict';

const fs = require('fs');

class PCAPWriter {
    constructor(filename) {
        this.fd = fs.openSync(filename, 'w');
        this.writeGlobalHeader();
        this.timestamp = 1700000000;
    }

    writeGlobalHeader() {
        // Magic 0xa1b2c3d4, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        const header = Buffer.alloc(24);
        header.writeUInt32LE(0xa1b2c3d4, 0);
        header.writeUInt16LE(2, 4);
        header.writeUInt16LE(4, 6);
        header.writeInt32LE(0, 8);
        header.writeUInt32LE(0, 12);
        header.writeUInt32LE(65535, 16);
        header.writeUInt32LE(1, 20);
        fs.writeSync(this.fd, header);
    }

    writePacket(data) {
        const tsSec = this.timestamp;
        const tsUsec = Math.floor(Math.random() * 1000000);
        this.timestamp++;

        const pktHeader = Buffer.alloc(16);
        pktHeader.writeUInt32LE(tsSec, 0);
        pktHeader.writeUInt32LE(tsUsec, 4);
        pktHeader.writeUInt32LE(data.length, 8);
        pktHeader.writeUInt32LE(data.length, 12);

        fs.writeSync(this.fd, pktHeader);
        fs.writeSync(this.fd, data);
    }

    close() {
        fs.closeSync(this.fd);
    }
}

function createEthernetHeader(srcMac, dstMac, etherType = 0x0800) {
    const dst = Buffer.from(dstMac.replace(/:/g, ''), 'hex');
    const src = Buffer.from(srcMac.replace(/:/g, ''), 'hex');
    const type = Buffer.alloc(2);
    type.writeUInt16BE(etherType, 0);
    return Buffer.concat([dst, src, type]);
}

function createIpHeader(srcIp, dstIp, protocol, payloadLen) {
    const versionIhl = 0x45;
    const tos = 0;
    const totalLen = 20 + payloadLen;
    const ident = Math.floor(Math.random() * 65535) + 1;
    const flagsFrag = 0x4000; // Don't fragment
    const ttl = 64;
    const checksum = 0;

    const header = Buffer.alloc(12);
    header.writeUInt8(versionIhl, 0);
    header.writeUInt8(tos, 1);
    header.writeUInt16BE(totalLen, 2);
    header.writeUInt16BE(ident, 4);
    header.writeUInt16BE(flagsFrag, 6);
    header.writeUInt8(ttl, 8);
    header.writeUInt8(protocol, 9);
    header.writeUInt16BE(checksum, 10);

    const src = Buffer.from(srcIp.split('.').map(Number));
    const dst = Buffer.from(dstIp.split('.').map(Number));

    return Buffer.concat([header, src, dst]);
}

function createTcpHeader(srcPort, dstPort, seq, ack, flags, payloadLen = 0) {
    const dataOffset = 5 << 4; // 20 bytes
    const window = 65535;
    const checksum = 0;
    const urgent = 0;

    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(srcPort, 0);
    tcp.writeUInt16BE(dstPort, 2);
    tcp.writeUInt32BE(seq, 4);
    tcp.writeUInt32BE(ack, 8);
    tcp.writeUInt8(dataOffset, 12);
    tcp.writeUInt8(flags, 13);
    tcp.writeUInt16BE(window, 14);
    tcp.writeUInt16BE(checksum, 16);
    tcp.writeUInt16BE(urgent, 18);

    return tcp;
}

function createUdpHeader(srcPort, dstPort, payloadLen) {
    const length = 8 + payloadLen;
    const checksum = 0;
    const udp = Buffer.alloc(8);
    udp.writeUInt16BE(srcPort, 0);
    udp.writeUInt16BE(dstPort, 2);
    udp.writeUInt16BE(length, 4);
    udp.writeUInt16BE(checksum, 6);
    return udp;
}

function createTlsClientHello(sni) {
    // SNI extension
    const sniBytes = Buffer.from(sni, 'ascii');
    const sniEntry = Buffer.alloc(3 + sniBytes.length);
    sniEntry.writeUInt8(0, 0); // type 0
    sniEntry.writeUInt16BE(sniBytes.length, 1);
    sniBytes.copy(sniEntry, 3);
    
    const sniList = Buffer.alloc(2 + sniEntry.length);
    sniList.writeUInt16BE(sniEntry.length, 0);
    sniEntry.copy(sniList, 2);

    const sniExt = Buffer.alloc(4 + sniList.length);
    sniExt.writeUInt16BE(0x0000, 0);
    sniExt.writeUInt16BE(sniList.length, 2);
    sniList.copy(sniExt, 4);

    // Supported versions
    const supportedVersions = Buffer.alloc(7);
    supportedVersions.writeUInt16BE(0x002b, 0);
    supportedVersions.writeUInt16BE(3, 2);
    supportedVersions.writeUInt8(2, 4);
    supportedVersions.writeUInt16BE(0x0304, 5);

    const extensions = Buffer.concat([sniExt, supportedVersions]);
    const extensionsData = Buffer.alloc(2 + extensions.length);
    extensionsData.writeUInt16BE(extensions.length, 0);
    extensions.copy(extensionsData, 2);

    // Client Hello body
    const clientVersion = Buffer.alloc(2);
    clientVersion.writeUInt16BE(0x0303, 0);
    
    const randomBytes = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) randomBytes[i] = Math.floor(Math.random() * 256);
    
    const sessionId = Buffer.alloc(1, 0);

    const cipherSuites = Buffer.alloc(6);
    cipherSuites.writeUInt16BE(4, 0);
    cipherSuites.writeUInt16BE(0x1301, 2); // TLS_AES_128_GCM
    cipherSuites.writeUInt16BE(0x1302, 4); // TLS_AES_256_GCM

    const compression = Buffer.alloc(2);
    compression.writeUInt8(1, 0);
    compression.writeUInt8(0, 1);

    const clientHelloBody = Buffer.concat([clientVersion, randomBytes, sessionId, cipherSuites, compression, extensionsData]);

    const handshake = Buffer.alloc(4 + clientHelloBody.length);
    handshake.writeUInt8(0x01, 0); // Client Hello
    handshake.writeUInt8((clientHelloBody.length >> 16) & 0xFF, 1);
    handshake.writeUInt8((clientHelloBody.length >> 8) & 0xFF, 2);
    handshake.writeUInt8(clientHelloBody.length & 0xFF, 3);
    clientHelloBody.copy(handshake, 4);

    const record = Buffer.alloc(5 + handshake.length);
    record.writeUInt8(0x16, 0); // TLS Handshake
    record.writeUInt16BE(0x0301, 1);
    record.writeUInt16BE(handshake.length, 3);
    handshake.copy(record, 5);

    return record;
}

function createHttpRequest(host, path = '/') {
    return Buffer.from(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n`);
}

function createDnsQuery(domain) {
    const txid = Buffer.alloc(2);
    txid.writeUInt16BE(Math.floor(Math.random() * 65535) + 1, 0);
    
    const flags = Buffer.alloc(2);
    flags.writeUInt16BE(0x0100, 0);

    const counts = Buffer.alloc(8);
    counts.writeUInt16BE(1, 0);
    counts.writeUInt16BE(0, 2);
    counts.writeUInt16BE(0, 4);
    counts.writeUInt16BE(0, 6);

    const parts = domain.split('.');
    let qLen = 0;
    for (const p of parts) qLen += 1 + p.length;
    qLen += 5; // null term + type + class

    const question = Buffer.alloc(qLen);
    let offset = 0;
    for (const p of parts) {
        question.writeUInt8(p.length, offset++);
        question.write(p, offset, 'ascii');
        offset += p.length;
    }
    question.writeUInt8(0, offset++);
    question.writeUInt16BE(1, offset);     // type A
    question.writeUInt16BE(1, offset + 2); // class IN

    return Buffer.concat([txid, flags, counts, question]);
}

function main() {
    if (process.argv[2] === '--help' || process.argv[2] === '-h') {
        console.log('Usage: node generateTestPcap.js');
        console.log('Generates a test_dpi.pcap file with test traffic for the DPI engine.');
        process.exit(0);
    }

    const writer = new PCAPWriter('test_dpi.pcap');
    
    const userMac = '00:11:22:33:44:55';
    const userIp = '192.168.1.100';
    const gatewayMac = 'aa:bb:cc:dd:ee:ff';
    
    const tlsConnections = [
        ['142.250.185.206', 'www.google.com', 443],
        ['142.250.185.110', 'www.youtube.com', 443],
        ['157.240.1.35', 'www.facebook.com', 443],
        ['157.240.1.174', 'www.instagram.com', 443],
        ['104.244.42.65', 'twitter.com', 443],
        ['52.94.236.248', 'www.amazon.com', 443],
        ['23.52.167.61', 'www.netflix.com', 443],
        ['140.82.114.4', 'github.com', 443],
        ['104.16.85.20', 'discord.com', 443],
        ['35.186.224.25', 'zoom.us', 443],
        ['35.186.227.140', 'web.telegram.org', 443],
        ['99.86.0.100', 'www.tiktok.com', 443],
        ['35.186.224.47', 'open.spotify.com', 443],
        ['192.0.78.24', 'www.cloudflare.com', 443],
        ['13.107.42.14', 'www.microsoft.com', 443],
        ['17.253.144.10', 'www.apple.com', 443]
    ];
    
    const httpConnections = [
        ['93.184.216.34', 'example.com', 80],
        ['185.199.108.153', 'httpbin.org', 80]
    ];
    
    const dnsQueries = [
        'www.google.com',
        'www.youtube.com',
        'www.facebook.com',
        'api.twitter.com'
    ];
    
    let seqBase = 1000;
    
    // Generate TLS packets
    for (const [dstIp, sni, dstPort] of tlsConnections) {
        let srcPort = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
        
        // TCP SYN
        let eth = createEthernetHeader(userMac, gatewayMac);
        let tcp = createTcpHeader(srcPort, dstPort, seqBase, 0, 0x02);
        let ip = createIpHeader(userIp, dstIp, 6, tcp.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp]));
        
        // TCP SYN-ACK
        tcp = createTcpHeader(dstPort, srcPort, seqBase + 1000, seqBase + 1, 0x12);
        ip = createIpHeader(dstIp, userIp, 6, tcp.length);
        eth = createEthernetHeader(gatewayMac, userMac);
        writer.writePacket(Buffer.concat([eth, ip, tcp]));
        
        // TCP ACK
        eth = createEthernetHeader(userMac, gatewayMac);
        tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x10);
        ip = createIpHeader(userIp, dstIp, 6, tcp.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp]));
        
        // TLS Client Hello with SNI
        const tlsData = createTlsClientHello(sni);
        tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x18);
        ip = createIpHeader(userIp, dstIp, 6, tcp.length + tlsData.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp, tlsData]));
        
        seqBase += 10000;
    }
    
    // Generate HTTP packets
    for (const [dstIp, host, dstPort] of httpConnections) {
        let srcPort = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
        
        // TCP SYN
        let eth = createEthernetHeader(userMac, gatewayMac);
        let tcp = createTcpHeader(srcPort, dstPort, seqBase, 0, 0x02);
        let ip = createIpHeader(userIp, dstIp, 6, tcp.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp]));
        
        // HTTP request
        const httpData = createHttpRequest(host);
        tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, 1, 0x18);
        ip = createIpHeader(userIp, dstIp, 6, tcp.length + httpData.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp, httpData]));
        
        seqBase += 10000;
    }
    
    // Generate DNS queries
    const dnsServer = '8.8.8.8';
    for (const domain of dnsQueries) {
        let srcPort = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
        
        const dnsData = createDnsQuery(domain);
        let eth = createEthernetHeader(userMac, gatewayMac);
        let udp = createUdpHeader(srcPort, 53, dnsData.length);
        let ip = createIpHeader(userIp, dnsServer, 17, udp.length + dnsData.length);
        writer.writePacket(Buffer.concat([eth, ip, udp, dnsData]));
    }
    
    // Add blocked IP traffic
    const blockedSourceIp = '192.168.1.50';
    for (let i = 0; i < 5; i++) {
        let srcPort = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
        let dstIp = '172.217.0.100';
        
        let eth = createEthernetHeader('00:11:22:33:44:56', gatewayMac);
        let tcp = createTcpHeader(srcPort, 443, seqBase, 0, 0x02);
        let ip = createIpHeader(blockedSourceIp, dstIp, 6, tcp.length);
        writer.writePacket(Buffer.concat([eth, ip, tcp]));
        
        seqBase += 1000;
    }
    
    writer.close();
    console.log(`Created test_dpi.pcap with test traffic`);
    console.log(`  - ${tlsConnections.length} TLS connections with SNI`);
    console.log(`  - ${httpConnections.length} HTTP connections`);
    console.log(`  - ${dnsQueries.length} DNS queries`);
    console.log(`  - 5 packets from blocked IP ${blockedSourceIp}`);
}

main();
