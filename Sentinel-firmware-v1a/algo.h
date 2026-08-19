#pragma once
//
// Algorand — SLIP-10 ed25519 m/44'/283'/0'/0'/0' (SLIP-44 coin type 283).
//
//   Derivation: SLIP-0010 ed25519 (same family as SOL/XLM/SUI/APT/NEAR).
//   Address:    base32(pubkey(32) || SHA-512/256(pubkey)[28:32]), no padding.
//               SHA-512/256 is a genuinely different hash from SHA-256 or
//               SHA-512 (own FIPS 180-4 initial hash value, truncated
//               output) — not available in the vendored trezor-crypto lib,
//               so it's built here by reusing sha512_Init/Update/Final with
//               the state overwritten to the SHA-512/256 IV right after Init.
//   Signing:    BLIND — signing message is "TX" || canonical-msgpack(txn);
//               app builds this and sends it raw, device just ed25519-signs
//               it directly (no on-device hash, like NEAR/Aptos — Algorand
//               prepends a fixed 2-byte ASCII prefix, not a hash digest).
//               App sends:    ALGO|acct|payloadHex
//               Device sends: ALGO-SIG> <64-byte ed25519 signature hex>
//
#include <Arduino.h>

namespace algo {

// base32 address (no padding) for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Raw 32-byte ed25519 public key (hex, no prefix) for account `index`.
// Needed app-side to independently compute the address (SHA-512/256 is
// already available in the app's crypto library) without a device round trip.
String pubKeyHex(const uint8_t *entropy, size_t entLen,
                 const char *passphrase, uint32_t index);

// Parse "ALGO|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// ed25519-sign the loaded payload directly (no on-device hashing). Returns
// 64-byte signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace algo
