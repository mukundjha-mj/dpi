// ============================================================================
// indexMT.js - Multi-threaded DPI Engine CLI entry point
// Converted from: src/dpi_mt.cpp
// ============================================================================
//
// Usage:
//   node indexMT.js <input.pcap> <output.pcap> [options]
//
// Options:
//   --lbs <n>              Number of load balancer instances (default: 2)
//   --fps <n>              FastPath workers per LB (default: 2)
//   --block-ip <ip>        Block source IP
//   --block-app <app>      Block application (YouTube, Facebook, etc.)
//   --block-domain <dom>   Block domain (substring match)
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
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection (JS)
=============================================================

Usage: node ${prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer instances (default: 2)
  --fps <n>              FP workers per LB (default: 2)

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
  └───┬───────┬───┘
      │       │    djb2(5-tuple) % fps_per_lb
      ▼       ▼
  ┌───┴───┐ ┌───┴───┐
  │  FPs  │ │  FPs  │  Worker threads: DPI, classification, blocking
  └───┬───┘ └───┬───┘
      │         │
      ▼         ▼
  ┌───┴───────┴───┐
  │ Output Writer │  Writes forwarded packets to output PCAP
  └───────────────┘

Example:
  node ${prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
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

    // Defaults (same as C++ dpi_mt.cpp)
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

    // Create and run the engine
    const engine = new DPIEngine({
        numLBs,
        numFastPathsPerLB: fpsPerLB,
        blockedApps,
        blockedIPs,
        blockedDomains,
    });

    await engine.start(inputFile, outputFile);
}

main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
