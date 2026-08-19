#pragma once
//
// Bitcoin Cash — BIP44 P2PKH m/44'/145'/0'/0/i, secp256k1.
//
// Deliberately a fully parallel signing path, NOT routed through the shared
// PSBT signer (signer.h/signer.cpp) that BTC/LTC/DOGE/DASH/DGB/RVN depend on
// — zero risk of regressing those. BCH needs two things standard PSBT can't
// give it:
//   1. Post-2018 BCH replay protection requires the BIP143 (segwit-style)
//      sighash algorithm for EVERY input, including plain P2PKH ones — not
//      just witness inputs like standard Bitcoin. The vendored PSBT signer
//      only uses BIP143 hashing for actual witness inputs.
//   2. SIGHASH_FORKID (0x40) ORed into the sighash byte — not a value the
//      shared signer's SigHashType enum/logic has any concept of.
//   Both come for free by reusing uBitcoin's low-level Tx::sigHashSegwit()
//   directly (it's a pure preimage calculator — it doesn't care whether the
//   input "is really" segwit) with a P2PKH scriptCode and sighash=0x41,
//   bypassing PSBT's opinionated per-input dispatch entirely.
//
//   Address: CashAddr — "bitcoincash:" + base32(version(1) || hash160(20) ||
//            checksum(5)), version byte 0x00 for P2PKH. Verified against the
//            spec's own official test vector (bitcoincash.org/spec/cashaddr),
//            not implemented from memory.
//   Signing: BLIND — app sends a compact binary description of the unsigned
//            transaction (inputs need amounts, which raw tx bytes don't
//            carry, so this isn't a standard raw-tx hex the device parses):
//              u8 numInputs
//              numInputs * { txid[32] (internal/reversed order) | vout u32 LE
//                            | amountSat u64 LE }
//              u8 numOutputs
//              numOutputs * { scriptLen u8 | script[scriptLen] | amountSat u64 LE }
//              locktime u32 LE
//            Device builds every input's scriptCode from its OWN derived
//            pubkey (single-address model, same as every other UTXO coin
//            here), signs each with SIGHASH_ALL|FORKID, and returns the full
//            signed raw transaction hex — same "device hands back a
//            broadcast-ready artifact" contract as the PSBT coins.
//            App sends:    BCH|acct|payloadHex
//            Device sends: BCH-SIGNED> <raw signed tx hex>
//
#include <Arduino.h>

namespace bch {

// CashAddr address ("bitcoincash:q...") for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Parse "BCH|acct|payloadHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the payload (on-screen verification).
String txHashHex();

// Sign every input and return the fully signed raw transaction hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace bch
