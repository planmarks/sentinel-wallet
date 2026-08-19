#pragma once
//
// Polkadot DOT — SLIP-10 ed25519 m/44'/354'/account', SS58 address (network 0).
//
//   Derivation: SLIP-0010 ed25519 m/44'/354'/account' (Ledger-compatible path).
//   Address:    SS58 encoding with Polkadot network prefix 0.
//               Checksum = Blake2b-512("SS58PRE" || 0x00 || pubkey)[0:2].
//               Encoded = base58([0x00 || pubkey || checksum]) — 35 bytes -> 48 chars starting with "1".
//   Signing:    BLIND — app sends SCALE extrinsic payload hex; device ed25519-signs it.
//               Per Substrate spec, if payload > 256 bytes the device hashes it first (Blake2b-256).
//               App sends:    DOT|acct|payloadHex
//               Device sends: DOT-SIG> <64-byte ed25519 signature hex>
//
#include <Arduino.h>

namespace dot {

// SS58 "1..." address for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Parse "DOT|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// ed25519-sign the loaded payload. Returns 64-byte signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace dot
