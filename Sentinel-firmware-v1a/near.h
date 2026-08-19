#pragma once
//
// NEAR — SLIP-10 ed25519 m/44'/397'/0'/0'/0' (SLIP-44 coin type 397).
//
//   Derivation: SLIP-0010 ed25519 (same family as SOL/XLM/SUI/APT).
//   Address:    lowercase hex(pubkey) — a NEAR "implicit account". Unlike
//               Sui/Aptos, this is NOT a hash — the address IS the pubkey,
//               same as SOL/XLM, so no separate raw-pubkey export is needed.
//   Signing:    BLIND — signing message is SHA-256(borsh(TransactionV0));
//               app builds the Borsh bytes and sends them raw, device
//               SHA-256-hashes then ed25519-signs (hash-then-sign, like Sui,
//               but SHA-256 instead of Blake2b).
//               App sends:    NEAR|acct|payloadHex   (borsh(TransactionV0))
//               Device sends: NEAR-SIG> <64-byte ed25519 signature hex>
//
#include <Arduino.h>

namespace near {

// lowercase hex address (== pubkey hex) for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Parse "NEAR|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// SHA-256 the loaded payload, then ed25519-sign it. Returns 64-byte
// signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace near
