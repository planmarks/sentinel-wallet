#pragma once
//
// Cosmos-SDK secp256k1 chains — Cosmos Hub (ATOM) and every other chain in
// the same family that uses plain secp256k1 (NOT Injective-style
// "ethsecp256k1", which is a genuinely different curve/address/signing
// scheme and out of scope here).
//   Derivation: BIP44 m/44'/118'/0'/0/i, secp256k1 — IDENTICAL across the
//               whole family (verified against each chain's chain-registry
//               entry: ATOM/DYDX/AXL/BABY all report slip44=118,
//               key_algos=["secp256k1"]) — only the bech32 HRP differs.
//   Address:    accountId = RIPEMD160(SHA256(compressedPubKey));
//               address   = bech32(hrp, accountId).
//   Signing: SIGN_MODE_DIRECT — the host builds the protobuf SignDoc and sends
//            its bytes; the device signs SHA256(SignDoc) with secp256k1 (low-s)
//            and returns the 64-byte compact signature (r||s). Blind-sign: the
//            device shows the SHA256 digest for on-host verification.
//            App sends:    TICKER|acct|signDocHex   (e.g. "DYDX|0|...")
//            Device sends: TICKER-SIG> <64-byte r||s hex>
//
#include <Arduino.h>

namespace cosmos {

// bech32 address for BIP44 account `index`, using the given HRP
// ("cosmos", "dydx", "axelar", "bbn", ...).
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index, const char *hrp);

// Parse a signing request "TICKER|acct|signDocHex" — `ticker` is the expected
// prefix (e.g. "DYDX"). Returns true if well-formed and the ticker matches.
bool loadTx(const String &line, const char *ticker);

// First 8 hex chars of the SHA256(SignDoc) digest (for on-screen verification).
String txHashHex();

// Sign the loaded SignDoc. Returns 64-byte r||s hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace cosmos
