#pragma once
//
// Sui — SLIP-10 ed25519 m/44'/784'/0'/0'/0' (SLIP-44 coin type 784).
//
//   Derivation: SLIP-0010 ed25519. Like SOL/XLM, ed25519 has no local
//               public-child derivation, so the app can't derive index>0
//               addresses from a cached pubkey alone — additional accounts
//               are reachable only via device-assisted ADDR_PROBE gap scan.
//   Address:    "0x" + hex(Blake2b-256(flag(0x00, ed25519) || pubkey)).
//   Signing:    BLIND — app sends the BCS-encoded IntentMessage<TransactionData>
//               bytes as hex; device Blake2b-256-hashes them (Sui always hashes,
//               regardless of length) and ed25519-signs the digest.
//               App sends:    SUI|acct|payloadHex
//               Device sends: SUI-SIG> <64-byte ed25519 signature hex>
//
#include <Arduino.h>

namespace sui {

// "0x..." address for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Raw 32-byte ed25519 public key (hex, no prefix) for account `index`.
// Unlike SOL/XLM, a Sui address is a Blake2b hash of the pubkey — not
// reversible — so the app needs the raw pubkey to build the serialized
// signature (flag || sig || pubkey) sent to Sui's executeTransaction.
String pubKeyHex(const uint8_t *entropy, size_t entLen,
                 const char *passphrase, uint32_t index);

// Parse "SUI|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// Blake2b-256 the loaded payload, then ed25519-sign it. Returns 64-byte
// signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace sui
