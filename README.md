# Packet Analyzer - DPI Engine

Deep Packet Inspection Engine - A high-performance, multi-threaded Node.js port of a low-level C++ network analyzer.

<div align="center">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D16.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js Version" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Mac%20%7C%20Linux-lightgrey?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" alt="Zero Dependencies" />
</div>

## Table of Contents

- [What is DPI?](#what-is-dpi)
- [Architecture](#architecture)
- [File Structure](#file-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [PCAP Reading](#pcap-reading)
  - [Packet Parsing](#packet-parsing)
  - [SNI Extraction](#sni-extraction)
  - [Flow Tracking](#flow-tracking)
  - [Blocking Engine](#blocking-engine)
- [Supported Applications](#supported-applications)
- [Multi-threading and Load Balancing](#multi-threading-and-load-balancing)
- [Sample Output](#sample-output)
- [Blocking Examples](#blocking-examples)
- [Performance Information](#performance-information)
- [Contributing](#contributing)
- [License](#license)

## What is DPI?

**Deep Packet Inspection (DPI)** is an advanced method of packet filtering that operates at the application layer of the OSI model. Unlike standard network firewalls which only look at IP addresses and port numbers (the headers), DPI examines the actual payload of the packet to identify, classify, and potentially block specific protocols or applications.

Real-world use cases for DPI include:
- **Parental Controls & Content Filtering:** Blocking social media, streaming services, or adult content on a network level.
- **Enterprise Security:** Detecting data exfiltration, malware signatures, or preventing the use of unauthorized VPN/Proxy tunnels.
- **QoS (Quality of Service) Traffic Shaping:** Throttling bandwidth-heavy video streaming applications to prioritize VoIP conferencing tools.
- **Network Analytics:** Categorizing usage statistics across a network to see app-level traffic distribution.

## Architecture

The engine features a full, parallel multi-threaded pipeline implemented using Node.js `worker_threads`, mimicking the original C++ threading architecture. The default configuration uses 2 Load Balancers (LBs) and 2 Fast Path Processors (FPs) per LB, yielding 4 worker threads.

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

## File Structure

```text
Root
│   package.json          - Project metadata and script aliases.
│   README.md             - This documentation file.
│   generateTestPcap.js   - Utility script to natively generate synthetic HTTP, HTTPS (TLS), and DNS test traffic.
│
└───src
    │   connectionTracker.js - Maintains the stateful flow table for active connections with bidirectional tracking.
    │   dpiEngine.js         - Orchestrates the full multi-threaded pipeline hooking up reader, LBs, and FPs.
    │   fastPath.js          - Worker thread logic for deep packet inspection, rule checking, and TLS parsing.
    │   index.js             - CLI entry point for the standard single-threaded DPI engine.
    │   indexMT.js           - CLI entry point for the multi-threaded worker DPI engine.
    │   loadBalancer.js      - Utilizes consistent hashing to distribute packets to FP workers.
    │   mainDpi.js           - Modular drop-in equivalent for `indexMT.js` with expanded architectural CLI help.
    │   mainSimple.js        - Diagnostic packet dumping utility (no output files, no blocking).
    │   packetParser.js      - Extracts exact offsets for Ethernet, IPv4, TCP, and UDP protocols.
    │   pcapReader.js        - Binary file reader capable of reading global and packet-level PCAP headers.
    │   ruleManager.js       - Stores and evaluates rule states for IP, application, and substring domains.
    │   sniExtractor.js      - Byte-level offset logic handling TLS Client Hello decoding and HTTP Host extractions.
    │   threadSafeQueue.js   - Promise-based FIFO delivery mechanism mirroring C++ std::condition_variable.
    │   types.js             - Common definitions, mapping enums, and AppType dictionaries.
```

## Installation

This project is built directly on the native Node.js API. It aggressively implements a **zero npm dependencies** footprint. No `npm install` or `node_modules/` is required to run the code.

```bash
# 1. Clone the repository
git clone https://github.com/mukundjha-mj/dpi.git
cd dpi

# 2. Check your Node.js version (Must be v16.0.0 or higher)
node --version
```

## Usage

### 1. Generate Test Data
Creates a synthetic capture file `test_dpi.pcap` filled with TLS, HTTP, and DNS packets spanning multiple simulated applications.
```bash
node generateTestPcap.js
```

### 2. Single-Threaded Mode
Runs everything sequentially in the main thread process. Recommended for small files or basic debugging.
```bash
node src/index.js test_dpi.pcap out.pcap
```

### 3. Multi-Threaded Mode
The fastest configuration. Runs processing in high-speed parallel workers.
```bash
node src/indexMT.js test_dpi.pcap out.pcap --lbs 2 --fps 4
```

### 4. Simple Diagnostic Dump
Dumps parsed frame output straight to standard output without blocking rules or generating an output PCAP.
```bash
node src/mainSimple.js test_dpi.pcap
```

### Command Line Flags

- `--block-app <app>`: Blocks an exact underlying application (e.g., `YouTube`, `Facebook`).
- `--block-domain <dom>`: Blocks a subset string of an SNI/Host (e.g., `tiktok.com`).
- `--block-ip <ip>`: Blocks an exact IP address.
- `--lbs <n>`: Override the LB threads count (default: 2, MT Mode only).
- `--fps <n>`: Override the number of fast-path workers per LB (default: 2, MT Mode only).

## How It Works

### PCAP Reading
To avoid external dependencies and massive memory bloat, `pcapReader.js` implements a raw binary reader conforming to libpcap 2.4 specifications. It checks the global file header bytes at offset 0 (`magicNumber`, `versionMajor`, `versionMinor`, `snaplen` at offset `16`, `network` link type at offset `20`). Packets are then continuously yielded by looping over 16-byte packet headers checking timestamps (`tsSec=0`, `tsUsec=4`) and lengths (`inclLen=8`, `origLen=12`), seamlessly detecting and resolving endianness swapping.

### Packet Parsing
The `packetParser.js` script slices buffers sequentially mirroring standard raw socket layers:
1. **Ethernet Header (0-13):** MAC strings generated directly via offsets `0` and `6`. EtherType is checked at `12`.
2. **IPv4 Header (Start = 14):** TTL checked at IP offset `8`. Transport Protocol matched out of offset `9`. Source IP extracted at offset `12` and Dst IP at `16` (big-endian).
3. **TCP/UDP Headers:** Start depends on `IHL * 4`. TCP identifies source/dest ports directly and checks `dataOffset / tcpHeaderLen` spanning offsets `12`/`13`.

### SNI Extraction
Deciphering TLS traffic natively is notoriously difficult. `sniExtractor.js` acts efficiently inside the TCP layer payload without using external cryptographical binders. It looks for a TLS Handshake record `Content Type == 0x16` and a `Client Hello` message (`[5] === 0x01`). Navigating past the explicit offsets for `Session ID` (43), `Cipher Suites`, and `Compression Methods`, it finally iterates over `Extensions`. Upon discovering Extension `0x0000` (SNI), it retrieves the dynamically bound string length and translates the direct binary buffer payload to `utf8`.

### Flow Tracking
Instead of tracking solitary packets, `connectionTracker.js` orchestrates flows using an industry-standard 5-Tuple Key:
`srcIp:srcPort-dstIp:dstPort-protocol`
To handle stateful, bidirectional packet sequences, the tracker actively hashes checks both directions. If `dstIp:dstPort-srcIp:srcPort-protocol` is already active, packets fall into the same context grouping, ensuring classification only has to happen statically on the first packet, boosting efficiency.

### Blocking Engine
The `ruleManager.js` ensures blocked packet sets don't propagate into output arrays. Upon configuration, an incoming DPI classification is prioritized sequentially based on three constraint types:
1. **IP Matching** (Extremely fast lookup via `Set`).
2. **App Matching** (Lowercase map matching on known categorical values).
3. **Domain Substring Matching** (Dynamic substring parsing within extracted TLS Client Hellos).

## Supported Applications

Using dynamic SNI and HTTP Header extraction (`types.js`), the engine categorizes flows specifically for traffic shaping properties. This supports:

| App Type | SNI Pattern Trigger |
| :--- | :--- |
| **Google** | `google`, `gstatic`, `googleapis`, `ggpht`, `gvt1` |
| **YouTube** | `youtube`, `ytimg`, `youtu.be`, `yt3.ggpht` |
| **Facebook** | `facebook`, `fbcdn`, `fb.com`, `fbsbx`, `meta.com` |
| **Instagram** | `instagram`, `cdninstagram` |
| **WhatsApp** | `whatsapp`, `wa.me` |
| **Netflix** | `netflix`, `nflxvideo`, `nflximg` |
| **Microsoft** | `microsoft`, `msn.com`, `office`, `azure`, `live.com`, `outlook`, `bing` |
| **Twitter / X** | `twitter`, `twimg`, `x.com`, `t.co` |
| **Amazon** | `amazon`, `amazonaws`, `cloudfront`, `aws` |
| **Apple** | `apple`, `icloud`, `mzstatic`, `itunes` |
| **Telegram** | `telegram`, `t.me` |
| **TikTok** | `tiktok`, `tiktokcdn`, `musical.ly`, `bytedance` |
| **Spotify** | `spotify`, `scdn.co` |
| **Zoom** | `zoom` |
| **Discord** | `discord`, `discordapp` |
| **GitHub** | `github`, `githubusercontent` |
| **Cloudflare** | `cloudflare`, `cf-` |

## Multi-threading and Load Balancing

Through `Worker` instantiation, threads are launched sequentially with serialized messaging utilizing `djb2` consistent string hashing. A flow key goes through:
```javascript
hash = ((hash << 5) + hash) + str.charCodeAt(i);
// Target LB = hash % numFastPaths
```
By binding hash logic explicitly, the engine asserts definitive Flow Affinity. In parallel structures, it's detrimental if TCP Sequence fragments hit isolated threads. The `loadBalancer.js` enforces that all identical keys end up passing into identical workers seamlessly. 

## Sample Output

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

## Blocking Examples

1. **Blocking a distinct Application Framework:**
   *Drop all Google and Facebook communication frames explicitly.*
   ```bash
   node src/indexMT.js in.pcap out.pcap --block-app Google --block-app Facebook
   ```

2. **Blocking a distinct Substring:**
   *Catch any stray TLS Hellos referencing anything regarding Apple infrastructure.*
   ```bash
   node src/indexMT.js in.pcap out.pcap --block-domain apple 
   ```

3. **Blocking raw Local Source IPs:**
   *Restrict all network bounds exiting local machines matching standard internal structures.*
   ```bash
   node src/indexMT.js in.pcap out.pcap --block-ip 192.168.1.50
   ```
   
4. **Combined Logic Targeting:**
   *Apply simultaneous rules to prevent traffic to TikTok servers alongside internal node blockage across 4 active LBs and 16 internal worker cores.*
   ```bash
   node src/indexMT.js in.pcap out.pcap --block-app TikTok --block-ip 192.168.1.100 --lbs 4 --fps 4
   ```

## Performance Information

This engine aggressively prioritizes speed and security logic. 
- **Zero NPM Dependencies:** Greatly nullifies injection-style NPM security vulnerabilities and guarantees offline/embedded portability.
- **True Parallel MT Architecture:** Uses `worker_threads` avoiding synchronous single-event-loop congestion limits.
- **Binary Zero-Copy:** Implemented entirely using native `Buffer` allocation mappings — ensuring packet headers are purely evaluated against indices without creating memory-taxing duplicated Substring copies.
- **Configurable Scalability:** Worker allocation is natively defined by user CLI preferences allowing deployment scales from embedded IoT single-cores to massive 128-core analytical cloud servers.

## Contributing
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
MIT License. See `LICENSE` for details.
