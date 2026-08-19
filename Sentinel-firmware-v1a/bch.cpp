#include "bch.h"
#include "wallet.h"

#include <Bitcoin.h>
#include <string.h>

// Trezor hash primitives compiled into the uBitcoin library.
extern "C" {
  void sha256_Raw(const uint8_t *data, uint32_t len, uint8_t digest[32]);
  void ripemd160(const uint8_t *msg, uint32_t msg_len, uint8_t *hash);
}

namespace {

static const char HEXCH[] = "0123456789abcdef";
static const char B32CH[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const size_t MAX_PAYLOAD = 2048;

static bool     s_loaded = false;
static uint32_t s_acct   = 0;
static uint8_t  s_payload[MAX_PAYLOAD];
static size_t   s_payloadLen = 0;

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// ---- CashAddr (bitcoincash.org/spec/cashaddr) -------------------------------
// Verified against the spec's own official test vector before use here:
// hash160 76a04053bda0a88bda5177b86a15c3b29f559873 (P2PKH, version 0x00) ->
// "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"

uint64_t cashaddrPolymod(const uint8_t *v, size_t len) {
  uint64_t c = 1;
  for (size_t i = 0; i < len; i++) {
    uint8_t c0 = (uint8_t)(c >> 35);
    c = ((c & 0x07ffffffffULL) << 5) ^ v[i];
    if (c0 & 0x01) c ^= 0x98f2bc8e61ULL;
    if (c0 & 0x02) c ^= 0x79b76d99e2ULL;
    if (c0 & 0x04) c ^= 0xf33e5fb3c4ULL;
    if (c0 & 0x08) c ^= 0xae2eabe2a8ULL;
    if (c0 & 0x10) c ^= 0x1e4f43e470ULL;
  }
  return c ^ 1;
}

// Regroup 8-bit bytes into 5-bit groups (pad with zero bits).
size_t convertbits8to5(const uint8_t *in, size_t inlen, uint8_t *out) {
  uint32_t acc = 0; int bits = 0; size_t o = 0;
  for (size_t i = 0; i < inlen; i++) {
    acc = (acc << 8) | in[i]; bits += 8;
    while (bits >= 5) { out[o++] = (acc >> (bits - 5)) & 31; bits -= 5; }
  }
  if (bits > 0) out[o++] = (acc << (5 - bits)) & 31;
  return o;
}

String cashAddrEncode(const uint8_t hash160[20]) {
  static const char *PREFIX = "bitcoincash";
  uint8_t versionAndHash[21];
  versionAndHash[0] = 0x00;  // P2PKH, 160-bit hash
  memcpy(versionAndHash + 1, hash160, 20);

  uint8_t payload5[40];
  size_t payloadLen = convertbits8to5(versionAndHash, sizeof(versionAndHash), payload5);

  size_t plen = strlen(PREFIX);
  uint8_t checkInput[64];
  size_t p = 0;
  for (size_t i = 0; i < plen; i++) checkInput[p++] = PREFIX[i] & 0x1F;
  checkInput[p++] = 0;  // separator
  for (size_t i = 0; i < payloadLen; i++) checkInput[p++] = payload5[i];
  for (int i = 0; i < 8; i++) checkInput[p++] = 0;  // checksum template

  uint64_t mod = cashaddrPolymod(checkInput, p);

  String out = String(PREFIX) + ":";
  for (size_t i = 0; i < payloadLen; i++) out += B32CH[payload5[i]];
  for (int i = 0; i < 8; i++) out += B32CH[(mod >> (5 * (7 - i))) & 31];
  return out;
}

// ---- key derivation ---------------------------------------------------------

bool derivePub(const uint8_t *entropy, size_t entLen, const char *passphrase,
               uint32_t index, HDPrivateKey &outChild) {
  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return false;
  HDPrivateKey root(m, String(passphrase ? passphrase : ""), &Mainnet);
  m = "";
  char path[40];
  snprintf(path, sizeof(path), "m/44h/145h/0h/0/%lu", (unsigned long)index);
  outChild = root.derive(path);
  return true;
}

bool pubKeyHash160(const HDPrivateKey &child, uint8_t hash160[20]) {
  PublicKey pub = child.publicKey();
  pub.compressed = true;
  uint8_t sec[33];
  if (pub.sec(sec, sizeof(sec)) != 33) return false;
  uint8_t sha[32]; sha256_Raw(sec, 33, sha);
  ripemd160(sha, 32, hash160);
  return true;
}

// ---- wire payload parsing ----------------------------------------------------

struct InInfo  { uint8_t txid[32]; uint32_t vout; uint64_t amount; };
struct OutInfo { uint8_t script[40]; uint8_t scriptLen; uint64_t amount; };

bool readU8(const uint8_t *buf, size_t len, size_t &off, uint8_t &v) {
  if (off + 1 > len) return false;
  v = buf[off]; off += 1; return true;
}
bool readU32LE(const uint8_t *buf, size_t len, size_t &off, uint32_t &v) {
  if (off + 4 > len) return false;
  v = (uint32_t)buf[off] | ((uint32_t)buf[off+1] << 8) | ((uint32_t)buf[off+2] << 16) | ((uint32_t)buf[off+3] << 24);
  off += 4; return true;
}
bool readU64LE(const uint8_t *buf, size_t len, size_t &off, uint64_t &v) {
  if (off + 8 > len) return false;
  v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | buf[off + i];
  off += 8; return true;
}
bool readBytes(const uint8_t *buf, size_t len, size_t &off, uint8_t *out, size_t n) {
  if (off + n > len) return false;
  memcpy(out, buf + off, n); off += n; return true;
}

}  // namespace

namespace bch {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  HDPrivateKey child;
  if (!derivePub(entropy, entLen, passphrase, index, child)) return String("");
  uint8_t hash160[20];
  if (!pubKeyHash160(child, hash160)) return String("");
  return cashAddrEncode(hash160);
}

bool loadTx(const String &line) {
  clearTx();
  // BCH|acct|payloadHex
  String parts[3]; int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 3; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i); start = i + 1;
    }
  }
  if (np < 3 || parts[0] != "BCH") return false;
  s_acct = (uint32_t)parts[1].toInt();

  const String &h = parts[2];
  if (h.length() == 0 || (h.length() & 1) || h.length() > MAX_PAYLOAD * 2) return false;
  s_payloadLen = h.length() / 2;
  for (size_t i = 0; i < s_payloadLen; i++) {
    int hi = hexVal(h[2 * i]), lo = hexVal(h[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    s_payload[i] = (uint8_t)((hi << 4) | lo);
  }
  s_loaded = true;
  return true;
}

String txHashHex() {
  if (!s_loaded || s_payloadLen == 0) return String("?");
  char buf[9];
  for (int i = 0; i < 4 && i < (int)s_payloadLen; i++) {
    buf[2 * i]     = HEXCH[s_payload[i] >> 4];
    buf[2 * i + 1] = HEXCH[s_payload[i] & 0x0F];
  }
  buf[8] = '\0';
  return String(buf);
}

String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase) {
  if (!s_loaded) return String("");

  HDPrivateKey child;
  if (!derivePub(entropy, entLen, passphrase, s_acct, child)) return String("");
  uint8_t hash160[20];
  if (!pubKeyHash160(child, hash160)) return String("");

  PublicKey pub = child.publicKey();
  pub.compressed = true;
  Script scriptCode(pub, P2PKH);  // OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG

  size_t off = 0;
  uint8_t nIn = 0;
  if (!readU8(s_payload, s_payloadLen, off, nIn) || nIn == 0) return String("");

  static InInfo ins[16];
  if (nIn > 16) return String("");
  for (uint8_t i = 0; i < nIn; i++) {
    if (!readBytes(s_payload, s_payloadLen, off, ins[i].txid, 32)) return String("");
    if (!readU32LE(s_payload, s_payloadLen, off, ins[i].vout)) return String("");
    if (!readU64LE(s_payload, s_payloadLen, off, ins[i].amount)) return String("");
  }

  uint8_t nOut = 0;
  if (!readU8(s_payload, s_payloadLen, off, nOut) || nOut == 0) return String("");
  static OutInfo outs[8];
  if (nOut > 8) return String("");
  for (uint8_t i = 0; i < nOut; i++) {
    if (!readU8(s_payload, s_payloadLen, off, outs[i].scriptLen)) return String("");
    if (outs[i].scriptLen > sizeof(outs[i].script)) return String("");
    if (!readBytes(s_payload, s_payloadLen, off, outs[i].script, outs[i].scriptLen)) return String("");
    if (!readU64LE(s_payload, s_payloadLen, off, outs[i].amount)) return String("");
  }

  uint32_t locktime = 0;
  if (!readU32LE(s_payload, s_payloadLen, off, locktime)) return String("");

  Tx tx;
  tx.version = 2;
  tx.locktime = locktime;
  for (uint8_t i = 0; i < nIn; i++) {
    tx.addInput(TxIn(ins[i].txid, ins[i].vout, 0xfffffffe));
  }
  for (uint8_t i = 0; i < nOut; i++) {
    Script outScript(outs[i].script, outs[i].scriptLen);
    tx.addOutput(TxOut(outs[i].amount, outScript));
  }

  const SigHashType FORKID_ALL = (SigHashType)0x41;  // SIGHASH_ALL | SIGHASH_FORKID
  for (uint8_t i = 0; i < nIn; i++) {
    uint8_t h[32];
    tx.sigHashSegwit(h, i, scriptCode, ins[i].amount, FORKID_ALL);
    Signature sig = child.sign(h);

    Script sc;
    sc.push(sig, FORKID_ALL);
    sc.push(pub);
    tx.txIns[i].scriptSig = sc;
  }

  return tx.serialize();
}

void clearTx() {
  s_loaded     = false;
  s_acct       = 0;
  s_payloadLen = 0;
  memset(s_payload, 0, sizeof(s_payload));
}

}  // namespace bch
