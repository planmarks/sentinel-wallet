#pragma once
//
// Filecoin FIL — native protocol (distinct from FEVM/"FILEVM", the EVM-
// compatible layer already handled generically by eth.cpp under chainId 314).
//
//   Derivation: BIP32 secp256k1 m/44'/461'/0'/0/index (SLIP-44 coin type 461).
//   Address:    "f1" + base32-lowercase-nopad(payload(20) || checksum(4)).
//               payload  = Blake2b-160(uncompressed 65-byte secp256k1 pubkey).
//               checksum = Blake2b-32bit(protocolByte(0x01) || payload).
//               Verified byte-for-byte against the 5 real f1 test vectors
//               published at spec.filecoin.io/appendix/address/.
//   Signing:    BLIND — app CBOR-encodes the Filecoin Message itself and
//               sends the bytes as hex; device just hashes+signs, no
//               on-device field decoding (same tier as dot.cpp).
//               Digest = Blake2b-256(CID_PREFIX(6 fixed bytes) ||
//                         Blake2b-256(messageCbor)) — Filecoin wraps the
//                         message hash in a CID before signing, not a plain
//                         single hash. CID_PREFIX = 01 71 a0 e4 02 20 (CIDv1 +
//                         dag-cbor codec + blake2b-256 multihash code+length
//                         varints — this exact 6-byte sequence is hardcoded
//                         as a constant in Zondax's own filecoin-signing-
//                         tools, signer/src/utils.rs).
//               Verified end-to-end (real private key -> digest -> signature)
//               against Zondax filecoin-signing-tools' test vectors
//               (txs.json / signed_message.json) in a throwaway Python
//               script — byte-for-byte match, including the recovery id.
//               Signature = r(32) || s(32) || recoveryId(1, range 0-3) —
//               Filecoin's convention, not Ethereum's 27+v; uBitcoin's
//               Signature::bin() already emits exactly this layout.
//               App sends:    FIL|acct|messageCborHex
//               Device sends: FIL-SIG> <65-byte signature hex>
//
#include <Arduino.h>

namespace fil {

// "f1..." address for account `index`.
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

// Parse "FIL|acct|messageCborHex". Returns true if well-formed.
bool loadTx(const String &line);

// First 8 hex chars of the CBOR payload (on-screen verification).
String txHashHex();

// secp256k1-sign the loaded message's CID-wrapped digest. Returns 65-byte
// r||s||recid signature hex, "" on failure.
String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase);

void clearTx();

}  // namespace fil
