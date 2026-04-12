# Packet Analyzer - DPI Engine

Deep Packet Inspection Engine - A high-performance, multi-threaded native Node.js network analyzer.

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

<div align="center">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D16.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js Version" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Mac%20%7C%20Linux-lightgrey?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" alt="Zero Dependencies" />
</div>

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview & Architecture](#3-project-overview--architecture)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Supported Applications](#10-supported-applications)
11. [Installation and Running](#11-installation-and-running)
12. [Understanding the Output](#12-understanding-the-output)
13. [Performance Information](#13-performance-information)
14. [Contributing & License](#14-contributing--license)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent).
- **Enterprises**: Block social media on office networks.
- **Parental Controls**: Block inappropriate websites.
- **Security**: Detect malware or intrusion attempts.

### What Our DPI Engine Does:
```text
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)
When you visit a website, data travels through multiple "layers":

```text
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure
Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```text
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IPv4 Header (20 bytes)                                       │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple
A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| **Source IP** | `192.168.1.100` | Who is sending |
| **Destination IP** | `172.217.14.206` | Where it's going |
| **Source Port** | `54321` | Sender's application identifier |
| **Destination Port** | `443` | Service being accessed (443 = HTTPS) |
| **Protocol** | `TCP (6)` | TCP or UDP limits |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we should block all of them.
- This bidirectional signature is how we statically "track" conversations.

### What is SNI?
**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:
1. Your browser sends a "Client Hello" message.
2. This message includes the domain name in **plaintext** (not encrypted yet!).
3. The server uses this to know which certificate to send.

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is explicitly visible in the first packet!

---

## 3. Project Overview & Architecture

### What This Project Does
```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Capture     │     │ DPI Engine  │     │ Output      │
│ (input.pcap)│ ──► │             │ ──► │ PCAP        │
└─────────────┘     │ - Parse     │     │ (filtered)  │
                    │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

The engine features a full, parallel multi-threaded pipeline implemented using Node.js `worker_threads`, mimicking native low-level thread architecture. The default configuration uses 2 Load Balancers (LBs) and 2 Fast Path Processors (FPs) per LB, yielding 4 worker threads.

```text
  ┌───────────────┐
  │  PCAP Reader  │  (Reads packets from input file)
  └───────┬───────┘
          │ djb2(5-tuple) % num_lbs
          ▼
  ┌───────┴───────┐
  │ Load Balancers│  (Distributes to worker FPs)
  │  LB0  │  LB1  │
  └───┬───┴───┬───┘
      │       │    djb2(5-tuple) % num_fps
      ▼       ▼
  ┌───┴───┐ ┌───┴───┐
  │ FP0-1 │ │ FP2-3 │  (Fast Path Worker Threads: parsing, TLS extraction, blocking)
  └───┬───┘ └───┬───┘
      │         │
      ▼         ▼
  ┌───┴───────┴───┐
  │ Output Writer │  (Collects forwarded packets and writes PCAP)
  └───────────────┘
```

---

## 4. File Structure

```text
packet_analyzer/
├── package.json          # Project metadata and dependencies.
├── README.md             # This documentation file.
├── generateTestPcap.js   # Generates test HTTP, TLS, and DNS traffic natively.
│
└───src/
    ├── connectionTracker.js # Stateful 5-tuple table & bidirectional flow tracking.
    ├── dpiEngine.js         # Orchestrator binding reader, Load Balancers, and Workers.
    ├── fastPath.js          # DPI Worker processing rule checks and SNI parsing.
    ├── index.js             # CLI entry for simple, single-threaded engine.
    ├── indexMT.js           # CLI entry for parallel multi-threaded engine.
    ├── loadBalancer.js      # Uses deterministic hashing for thread routing.
    ├── mainDpi.js           # Alternative MT drop-in with C++ style UI charts.
    ├── mainSimple.js        # Packet dumping tool (no output PCAP or blocking).
    ├── packetParser.js      # Decodes byte offsets for Ethernet, IPv4, TCP/UDP.
    ├── pcapReader.js        # Reads raw PCAP headers from binary packet streams.
    ├── ruleManager.js       # Stores IP/App/Domain priority blocking policies.
    ├── sniExtractor.js      # Decodes TLS Handshake offset algorithms.
    ├── threadSafeQueue.js   # Promise-based queue mimicking std::condition_variable.
    └── types.js             # Constant enums and map classification strings.
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through the single-threaded `index.js`:

### Step 1: Read PCAP File
```javascript
const pcapBuf = openPcap("capture.pcap");
readGlobalHeader(pcapBuf);
```
**What happens:**
1. Open the file directly into a raw Node `Buffer`.
2. Read the 24-byte global header (magic number, capture timestamp configurations).
3. Detect architecture endianness natively.

### Step 2: Yield Each Packet
```javascript
for (const pkt of readPackets(pcapBuf)) {
    // pkt.data contains raw bytes
    // pkt.inclLen contains byte constraints
}
```

### Step 3: Parse Protocol Headers
```javascript
const parsed = parsePacket(pkt.data);
```
**What happens (in `packetParser.js`):**
- **Ethernet (0-13):** MAC hardware identifiers, verifies EtherType is IPv4.
- **IPv4 (Start 14):** Checks length, pulls Src/Dst IP directly out of `buffer.readUInt32BE(16)`.
- **TCP/UDP:** Translates the nested Source/Destination application ports from underlying slice.

### Step 4: Create Flow Lookup
```javascript
const key = `${parsed.srcIp}:${parsed.srcPort}-${parsed.dstIp}:${parsed.dstPort}-${parsed.protocol}`;
const flow = tracker.getOrCreateFlow(key, pkt, parsed);
```
Flow tracking uses Bidirectional Keys to ensure data heading back from the server inherits the exact same policies generated by the outgoing request!

### Step 5: Extract SNI (Deep Packet Inspection)
```javascript
// Ensure it's a TLS Payload
if (parsed.hasTcp && parsed.dstPort === 443) {
    const sni = extractSNI(pkt.data.subarray(parsed.payloadOffset));
    if (sni !== null) {
         flow.sni = sni;
         flow.appType = sniToAppType(sni);
    }
}
```

### Step 6: Verify Flow Blocking Policies
```javascript
if (rules.isBlocked(parsed.srcIp, flow.appType, flow.sni)) {
    flow.blocked = true;
}
```
**What happens (in `ruleManager.js`):**
Rules strictly fire in constraint order utilizing optimized Maps/Sets instead of loops for performance:
1. Is Source IP explicitly blocked? -> `DROP`
2. Does App String match blacklists? -> `DROP`
3. Does the Domain String map match? -> `DROP`

### Step 7: Forward or Drop
```javascript
if (flow.blocked) {
    dropped++;
    // Packet is ignored.
} else {
    forwarded++;
    outputPCAP.write(pkt.header);
    outputPCAP.write(pkt.data);
}
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The pure-parallel `indexMT.js` relies strictly on Node.js `worker_threads` for scaling performance dynamically across high-core systems.

### Load Balancers (LBs) & Fast Paths (FPs)
1. **LBs** receive traffic linearly from the disk reader. They execute the initial structural parsing.
2. **Deterministic Hashing:** LBs dictate which FP receives the packet. A unified connection **must** persist on the exact same thread to safely monitor flows without complex asynchronous `Mutex` locking.

### DJB2 Flow Affinity Algorithm
```javascript
// In src/loadBalancer.js
let hash = 5381;
for (let i = 0; i < flowKeyString.length; i++) {
    hash = ((hash << 5) + hash) + flowKeyString.charCodeAt(i);
}
const designatedWorker = workers[hash % numberOfFPs];
```
*Why this matters:*
- Packet 1 (SYN) → Hash computes `FP2`
- Packet 4 (Client Hello / TLS) → Hash computes `FP2`
- All states remain naturally concurrent!

### Thread-Safe Architecture
To communicate without collision, the engine pushes frames across message channels into an `AsyncQueue`. Using unresolved `Promise` arrays, worker event-loops suspend gracefully when the queue empties, preventing hyper-active CPU spins.

---

## 7. Deep Dive: Each Component

- **`pcapReader.js`:** Native binary parser that navigates through timestamp chunks and prevents heavy `fs.readFileSync` arrays when iterating sequentially. Checks global file header bytes at offset 0 (`magicNumber`, `versionMajor`).
- **`packetParser.js`:** Slices buffers reflecting raw socket offsets. `TCP DataOffset` math determines the true payload start boundary dynamically bypassing variable size HTTP fields.
- **`sniExtractor.js`:** Navigates directly inside the TCP layer payload without using external cryptographical libraries to pinpoint the Client Hello extension arrays.
- **`connectionTracker.js`:** Reverses inbound packets to fetch origin states. Allows TCP payload chunks containing no SNI to automatically adopt the classification previously fetched by the original Client Hello frame!

---

## 8. How SNI Extraction Works

### The TLS Handshake (Visualized)
```text
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```
We can only extract SNI from the **first Client Hello**!

### Our Extraction Snippet
Decoding TLS natively is a meticulous process of tracking byte pointers:
```javascript
// src/sniExtractor.js
function extractSNI(payload) {
    if (payload[0] !== 0x16) return null; // Not Handshake
    if (payload[5] !== 0x01) return null; // Not Client Hello
    
    let offset = 43; // Safely skip to Session ID
    
    offset += 1 + payload[offset]; // Skip Session ID Length
    
    const cipherLen = payload.readUInt16BE(offset);
    offset += 2 + cipherLen; // Skip Ciphers
    
    const compLen = payload[offset];
    offset += 1 + compLen; // Skip Compression Methods
    
    const extTotalLen = payload.readUInt16BE(offset);
    offset += 2;
    
    const end = offset + extTotalLen;
    while (offset + 4 <= end) {
        const type = payload.readUInt16BE(offset);
    	const len = payload.readUInt16BE(offset + 2);
    	offset += 4;
    	
    	if (type === 0x0000) { // Discovered SNI Extension
    	    const stringLen = payload.readUInt16BE(offset + 3);
    	    return payload.toString('utf8', offset + 5, offset + 5 + stringLen);
    	}
    	offset += len;
    }
    return null;
}
```

---

## 9. How Blocking Works

**Important:** We block at the *flow* level, not packet level!
```text
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
```
*Why?* Applications connect over TCP before firing TLS protocols. By applying persistent boolean properties inside `connectionTracker.js`, we seamlessly strangle subsequent packets dynamically causing client-side session timeouts.

---

## 10. Supported Applications

By inspecting dynamic SNI algorithms (`types.js`), the engine natively tags specific services for reporting and blocking. Supported subsets include:

| App Type | SNI Pattern Trigger |
| :--- | :--- |
| **Google** | `google`, `gstatic`, `googleapis`, `ggpht` |
| **YouTube** | `youtube`, `ytimg`, `youtu.be`, `yt3.ggpht` |
| **Facebook** | `facebook`, `fbcdn`, `fb.com`, `meta.com` |
| **Instagram** | `instagram`, `cdninstagram` |
| **WhatsApp** | `whatsapp`, `wa.me` |
| **Netflix** | `netflix`, `nflxvideo`, `nflximg` |
| **Microsoft** | `microsoft`, `msn.com`, `azure`, `live.com` |
| **Twitter / X** | `twitter`, `twimg`, `x.com`, `t.co` |
| **Amazon** | `amazon`, `amazonaws`, `cloudfront`, `aws` |
| **Apple** | `apple`, `icloud`, `mzstatic`, `itunes` |
| **Telegram** | `telegram`, `t.me` |
| **TikTok** | `tiktok`, `tiktokcdn`, `musical.ly` |
| **Spotify** | `spotify`, `scdn.co` |
| **Zoom** | `zoom` |
| **Discord** | `discord`, `discordapp` |
| **GitHub** | `github`, `githubusercontent` |
| **Cloudflare**| `cloudflare`, `cf-` |

---

## 11. Installation and Running

This project strictly utilizes native features and implements a **zero npm dependencies** footprint. No `npm install` applies.

### Prerequisites & Creation
```bash
# Clone
git clone https://github.com/mukundjha-mj/dpi.git
cd dpi

# Verify version (>= v16.0.0)
node --version

# Generate test synthetic networks mapping 77 diagnostic sequences!
node generateTestPcap.js
```

### Running the Engine
**Single-Threaded Context:**
```bash
node src/index.js test_dpi.pcap out.pcap
```

**Multi-Threaded Scale:**
```bash
node src/indexMT.js test_dpi.pcap out.pcap --lbs 2 --fps 4
```

**Blocking Exact Frames:**
```bash
node src/indexMT.js in.pcap out.pcap \
    --block-app YouTube \
    --block-app Facebook \
    --block-ip 192.168.1.50 \
    --block-domain custom-target.org \
    --fps 8
```

---

## 12. Understanding the Output

```text
╔══════════════════════════════════════════════════════════════╗
║                     DPI ENGINE v1.0 (JS)                     ║
║                Deep Packet Inspection System                 ║
╠══════════════════════════════════════════════════════════════╣
║ Configuration:                                               ║
║   Load Balancers:               2                            ║
║   FPs per LB:                   2                            ║
║   Total FP threads:             4                            ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                 77                            ║
║ Total Bytes:                 5738                            ║
║ TCP Packets:                   73                            ║
║ UDP Packets:                    4                            ║
║ Forwarded:                     68                            ║
║ Dropped:                        9                            ║
║ Drop Rate:                 11.69%                            ║
╠══════════════════════════════════════════════════════════════╣
║ LOAD BALANCER STATISTICS                                     ║
║   LB0 Dispatched:              38                            ║
║   LB1 Dispatched:              39                            ║
╚══════════════════════════════════════════════════════════════╝
```

| Output Category | Description of Insight |
|---------|---------|
| **Configuration** | Current worker distribution topology created visually. |
| **Report Status** | The breakdown of captured sequences, packet forwarding counts, and exact mathematical drop ratios. |
| **Load Balancing** | Debug data validating that the internal `djb2` routing algorithms are distributing traffic harmoniously instead of over-saturating a single memory core. |

---

## 13. Extending the Project 

### Ideas for Improvement
1. **Add Real-Time Interfaces:** Pipe output arrays via WebSockets natively onto an Express backend locally rendering a user-interface chart.
2. **Build Bandwidth Rate-Limits:** Instead of rejecting packets on boolean matches, delay `.write()` queues incrementally. 
3. **HTTP3 (QUIC) Engine Extraction:** Inspect UDP structures directly on port 443 recognizing initial Initial framing cryptography.
4. **Persistent JSON Storage:** Allow `--config config.json` for mapping blacklists instead of long CLI strings.

---

## Performance Information
- **Node.js Parallel Environment:** Built to completely ignore event loop restrictions using V8 `worker_threads`.
- **Binary Zero-Copy Extraction:** `Buffer.subarray()` ensures gigabytes of PCAP files aren't duplicating arrays under variable garbage collection constraints.
- **Portability:** Instantly compatible on Windows, macOS, and Linux without worrying about complex or external build dependencies. 

---

## 14. Contributing & License

Feel free to fork, optimize the buffer loops, or submit pull requests adding comprehensive `AppType` detection frameworks!
Licensed under the **MIT License**.
