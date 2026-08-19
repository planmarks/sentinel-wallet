#pragma once
//
// Aptos — SLIP-10 ed25519 m/44'/637'/0'/0'/0' (SLIP-44 coin type 637).
//
//   Derivation: SLIP-0010 ed25519 (same family as SOL/XLM/SUI).
//   Address:    "0x" + hex(SHA3-256(pubkey || 0x00)) — real NIST SHA3-256,
//               NOT Ethereum's Keccak-256 (different padding, different hash).
//   Signing:    BLIND — no on-device hash, unlike Sui/Substrate. Aptos's
//               signing message is `seed || bcs(RawTransaction)` where
//               `seed = SHA3-256("APTOS::RawTransaction")` is a fixed 32-byte
//               constant; ed25519 hashes internally as part of standard EdDSA,
//               so the app precomputes the seed once and the device just
//               ed25519-signs whatever bytes it's given, no extra hashing.
//               App sends:    APT|acct|payloadHex   (seed || bcs(RawTransaction))
//               Device sends: APT-SIG> <64-byte ed25519 signature hex>
//
#include <Arduino.h>

namespace apt {

// "0x..." address for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Raw 32-byte ed25519 public key (hex, no prefix) for account `index`.
// Needed app-side to build the TransactionAuthenticator::Ed25519 envelope.
String pubKeyHex(const uint8_t *entropy, size_t entLen,
                 const char *passphrase, uint32_t index);

// Parse "APT|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// ed25519-sign the loaded payload directly (no on-device hashing). Returns
// 64-byte signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace apt
