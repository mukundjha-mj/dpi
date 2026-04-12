// ============================================================================
// mainDpi.js - Full DPI Engine CLI entry point (component-based)
// Converted from: src/main_dpi.cpp
// ============================================================================
//
// This mirrors main_dpi.cpp which uses the modular DPIEngine class from
// dpi_engine.h / dpi_engine.cpp.  It is functionally equivalent to
// indexMT.js but includes the extended help text and architecture diagram
// from the C++ version.
//
// Usage:
//   node mainDpi.js <input.pcap> <output.pcap> [options]
//
// ============================================================================

'use strict';

const path = require('path');
const { DPIEngine } = require('./dpiEngine');

// ============================================================================
// Usage / Help
// ============================================================================

function printUsage(prog) {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0 (JS)                     ║
║               Deep Packet Inspection System                 ║
╚══════════════════════════════════════════════════════════════╝

Usage: node ${prog} <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer instances (default: 2)
  --fps <n>              FP workers per LB (default: 2)
  --help, -h             Show this help

Examples:
  node ${prog} capture.pcap filtered.pcap
  node ${prog} capture.pcap filtered.pcap --block-app YouTube
  node ${prog} capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain tiktok.com

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌───────────────┐
  │  PCAP Reader  │  Reads packets from input file
  └───────┬───────┘
          │ djb2(5-tuple) % num_lbs
          ▼
  ┌───────┴───────┐
  │ Load Balancer │  LB instances distribute to FPs
  │  LB0  │  LB1  │
  └───┬───┴───┬───┘
      │       │    djb2(5-tuple) % fps_per_lb
      ▼       ▼
  ┌───┴───┐ ┌───┴───┐
  │ FP0-1 │ │ FP2-3 │  Worker threads: DPI, classification, blocking
  └───┬───┘ └───┬───┘
      │         │
      ▼         ▼
  ┌───┴───────┴───┐
  │ Output Writer │  Writes forwarded packets to output PCAP
  └───────────────┘
`);
}

// ============================================================================
// Main
// ============================================================================

async function main() {
    const args = process.argv.slice(2);

    if (args.length < 2 || args.includes('--help') || args.includes('-h')) {
        printUsage(path.basename(process.argv[1]));
        process.exit(args.length < 2 ? 1 : 0);
    }

    const inputFile  = args[0];
    const outputFile = args[1];

    // Defaults matching main_dpi.cpp
    let numLBs = 2;
    let fpsPerLB = 2;

    const blockedIPs     = [];
    const blockedApps    = [];
    const blockedDomains = [];

    // Parse CLI options
    for (let i = 2; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--block-ip' && i + 1 < args.length) {
            blockedIPs.push(args[++i]);
        } else if (arg === '--block-app' && i + 1 < args.length) {
            blockedApps.push(args[++i]);
        } else if (arg === '--block-domain' && i + 1 < args.length) {
            blockedDomains.push(args[++i]);
        } else if (arg === '--lbs' && i + 1 < args.length) {
            numLBs = parseInt(args[++i], 10);
        } else if (arg === '--fps' && i + 1 < args.length) {
            fpsPerLB = parseInt(args[++i], 10);
        }
    }

    // Create and run DPI engine
    const engine = new DPIEngine({
        numLBs,
        numFastPathsPerLB: fpsPerLB,
        blockedApps,
        blockedIPs,
        blockedDomains,
    });

    await engine.start(inputFile, outputFile);

    console.log('\nProcessing complete!');
}

main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
