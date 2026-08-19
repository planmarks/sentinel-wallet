#pragma once
//
// XRP Ledger support.
//   Address: BIP44 m/44'/144'/0'/0/i, secp256k1.
//            AccountID = RIPEMD160(SHA256(compressedPubKey)).
//            Address   = XRP-base58check(0x00 + AccountID).
//            XRP alphabet: rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
//   Signing: Firmware receives semantic fields and constructs the full canonical
//            XRPL binary-serialized transaction including SigningPubKey.
//            SHA-512-half of (0x53545800 + canonical_tx_bytes) is the signing digest.
//   Native XRP:      App sends:    XRP|acct|seq|amountDrops|feeDrops|destAccountIdHex
//                    Device sends: XRP-SIGNED> <complete-signed-tx-hex>
//   Issued currency  App sends:    XRPT|acct|seq|exp|mantissa|currencyHex|issuerAccountIdHex|
//   (e.g. RLUSD):                  feeDrops|destAccountIdHex
//                    Device sends: RLUSD-SIGNED> <complete-signed-tx-hex>
//   TrustSet         App sends:    XRPTRUST|acct|seq|exp|mantissa|currencyHex|
//   (opt in to hold                issuerAccountIdHex|feeDrops
//   an issued                      (no destination — TrustSet has none; the
//   currency)                      counterparty is the issuer inside LimitAmount)
//                    Device sends: TRUSTSET-SIGNED> <complete-signed-tx-hex>
//   RLUSD and TrustSet both sign under the same COIN_XRP as native XRP (same
//   account/key) — loadTx() auto-detects which shape a line is from its
//   first token ("XRP"/"XRPT"/"XRPTRUST"), so no new on-device coin id or
//   dispatch-site changes were needed anywhere in coldwallet.ino beyond
//   doSign()'s label and renderXrpReview()'s title, both driven by
//   isIssuedTx()/isTrustSetTx(). TrustSet's LimitAmount reuses the exact
//   same issued-currency Amount encoding as a Payment's Amount field (same
//   exp/mantissa/currency/issuer shape), just a different field code (6,3
//   instead of 6,1) — confirmed by decoding a real historical TrustSet
//   transaction's raw bytes off mainnet, not assumed. Flags is always
//   tfSetNoRipple (0x00020000), the standard default for a plain
//   token-holding trustline that isn't meant to be used as a payment path,
//   matching what that same real transaction used.
//   `exp`/`mantissa` are the XRPL issued-currency Amount field's exponent
//   (signed decimal, range -96..80) and mantissa (unsigned decimal,
//   normalized to 10^15..10^16-1 by the app before sending) — firmware only
//   bit-packs them, never parses or normalizes a decimal amount string
//   itself. `currencyHex`/`issuerAccountIdHex` are 40 hex chars (20 bytes)
//   each, the XRPL 160-bit currency-code and issuer-AccountID formats.
//
#include <Arduino.h>

namespace xrp {

// XRP address for BIP44 account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Parse a signing request. Returns true if the line is well-formed. Accepts
// the native ("XRP|..."), issued-currency Payment ("XRPT|..."), and
// TrustSet ("XRPTRUST|...") line shapes — see the format notes above.
bool loadTx(const String &line);

// True if the currently loaded tx is an issued-currency Payment (loaded via
// an "XRPT|..." line), false for a plain native-XRP Payment or a TrustSet.
// Valid after a successful loadTx(); mirrors ada::needsStakeWitness()'s
// accessor pattern.
bool isIssuedTx();

// True if the currently loaded tx is a TrustSet (loaded via an
// "XRPTRUST|..." line). Valid after a successful loadTx().
bool isTrustSetTx();

// Display helpers (valid after loadTx).
// Returns first 8 hex chars of the destination AccountID for on-screen verification.
String txHashHex();

// Sign the loaded tx and return the complete signed transaction hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace xrp
