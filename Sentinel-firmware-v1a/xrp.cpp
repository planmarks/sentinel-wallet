#include "xrp.h"
#include "wallet.h"

#include <Bitcoin.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

// Trezor hash primitives compiled into the uBitcoin library.
extern "C" {
  void sha256_Raw(const uint8_t *data, uint32_t len, uint8_t digest[32]);
  void sha512_Raw(const uint8_t *data, uint32_t len, uint8_t digest[64]);
  void ripemd160(const uint8_t *msg, uint32_t msg_len, uint8_t *hash);
}

// ============================================================================
// helpers (file-local)
// ============================================================================
namespace {

static const char HEXCH[] = "0123456789abcdef";

// XRP base58check alphabet (for address generation only).
static const char XRP_ALPHA[] =
    "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

static int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// XRP base58check encoding (for address display).
static String xrpBase58Check(const uint8_t *data, int len) {
  int leadZeros = 0;
  while (leadZeros < len && data[leadZeros] == 0) leadZeros++;

  uint8_t tmp[32];
  if (len > (int)sizeof(tmp)) return String("");
  memcpy(tmp, data, len);

  char digits[40];
  int dlen = 0;
  bool nonzero;
  do {
    uint32_t rem = 0;
    nonzero = false;
    for (int i = 0; i < len; i++) {
      uint32_t cur = rem * 256u + tmp[i];
      tmp[i] = (uint8_t)(cur / 58u);
      rem    = cur % 58u;
      if (tmp[i]) nonzero = true;
    }
    if (dlen < (int)sizeof(digits) - 1) digits[dlen++] = XRP_ALPHA[rem];
  } while (nonzero);
  for (int i = 0; i < leadZeros && dlen < (int)sizeof(digits) - 1; i++)
    digits[dlen++] = XRP_ALPHA[0];
  for (int i = 0, j = dlen - 1; i < j; i++, j--) {
    char t = digits[i]; digits[i] = digits[j]; digits[j] = t;
  }
  digits[dlen] = '\0';
  return String(digits);
}

// ---- XRP binary serialization helpers ----

// Write a UInt16 field (type=1, single-byte header, 2-byte big-endian value).
static void writeUInt16Field(std::vector<uint8_t> &out, uint8_t hdr, uint16_t v) {
  out.push_back(hdr);
  out.push_back(v >> 8);
  out.push_back(v & 0xFF);
}

// Write a UInt32 field (type=2, single-byte header, 4-byte big-endian value).
static void writeUInt32Field(std::vector<uint8_t> &out, uint8_t hdr, uint32_t v) {
  out.push_back(hdr);
  out.push_back((v >> 24) & 0xFF);
  out.push_back((v >> 16) & 0xFF);
  out.push_back((v >>  8) & 0xFF);
  out.push_back( v        & 0xFF);
}

// Write a native XRP Amount field (type=6): 0x4000000000000000 | drops, big-endian.
static void writeAmountField(std::vector<uint8_t> &out, uint8_t hdr, uint64_t drops) {
  out.push_back(hdr);
  uint64_t enc = 0x4000000000000000ULL | drops;
  for (int i = 7; i >= 0; i--) out.push_back((enc >> (i * 8)) & 0xFF);
}

// Write a VL-prefixed blob field (type=7).  len must be < 193.
static void writeBlobField(std::vector<uint8_t> &out, uint8_t hdr,
                           const uint8_t *data, size_t len) {
  out.push_back(hdr);
  out.push_back((uint8_t)len);
  for (size_t i = 0; i < len; i++) out.push_back(data[i]);
}

// Write a VL-prefixed AccountID field (type=8, always 20 bytes).
static void writeAccountField(std::vector<uint8_t> &out, uint8_t hdr,
                              const uint8_t accId[20]) {
  writeBlobField(out, hdr, accId, 20);
}

// Write an XRPL issued-currency Amount field (type=6): the customized-float
// encoding (not-XRP bit + positive-sign bit + biased exponent + mantissa,
// 8 bytes) followed by the fixed-width 160-bit currency code and 160-bit
// issuer AccountID (no VL length prefix — confirmed against xrpl.org's
// binary-format spec and cross-verified byte-for-byte against xrpl-py's
// amount.py/constants.py source, not derived from memory): exponent bias
// is +97 (stored range 0..177 for the real -96..80 range), mantissa is
// normalized to 10^15..10^16-1 by the app before this is ever called —
// firmware only bit-packs the already-normalized fields, it never parses
// or normalizes a decimal amount string itself. Always encodes positive
// (bit 62 set) since a Payment amount is never negative.
static void writeIssuedAmountField(std::vector<uint8_t> &out, uint8_t hdr,
                                    int32_t exp, uint64_t mantissa,
                                    const uint8_t currency[20],
                                    const uint8_t issuer[20]) {
  out.push_back(hdr);
  uint64_t enc = 0x8000000000000000ULL           // "not XRP"
               | 0x4000000000000000ULL           // positive
               | (((uint64_t)(exp + 97)) << 54)   // biased exponent
               | mantissa;
  for (int i = 7; i >= 0; i--) out.push_back((enc >> (i * 8)) & 0xFF);
  for (int i = 0; i < 20; i++) out.push_back(currency[i]);
  for (int i = 0; i < 20; i++) out.push_back(issuer[i]);
}

// Decode a 40-hex-char string into a 20-byte buffer. Shared by every
// AccountID/currency-code field this module parses off the wire.
static bool hex20(const String &s, uint8_t out[20]) {
  if (s.length() != 40) return false;
  for (int i = 0; i < 20; i++) {
    int hi = hexVal(s[2 * i]), lo = hexVal(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// ---- transaction state ----
static bool     s_loaded  = false;
static bool     s_isIssued = false;  // true = issued-currency Payment (e.g. RLUSD)
static bool     s_isTrustSet = false;  // true = TrustSet (opt in to hold an issued currency)
static uint32_t s_acct    = 0;
static uint32_t s_seq     = 0;
static uint64_t s_amount  = 0;   // native Payment only: drops
// Issued Payment: Amount's exponent/mantissa/currency/issuer.
// TrustSet: LimitAmount's exponent/mantissa/currency/issuer (identical
// field shape, just a different field code — see writeIssuedAmountField's
// callers in buildForSigning()/buildTrustSetForSigning()).
static int32_t  s_exp     = 0;
static uint64_t s_mantissa = 0;
static uint8_t  s_currency[20];
static uint8_t  s_issuerAccId[20];
static uint64_t s_fee     = 0;   // always native XRP drops
static uint8_t  s_destAccId[20];  // Payment only — TrustSet has no destination

// Build the canonical serialized tx fields for signing (all fields in
// (typeCode, fieldCode) order, with SigningPubKey, without TxnSignature).
// `accountFieldOffsetOut` receives the exact byte offset the Account field
// starts at — needed by buildSignedTx() to splice in TxnSignature just
// before it. This used to be a hardcoded literal (66) that only stayed
// correct because every field before Account was fixed-size; an
// issued-currency Amount is a different size (49 bytes vs 9), so the real
// offset is now computed here instead of assumed.
static std::vector<uint8_t> buildForSigning(const uint8_t pubkey[33],
                                            const uint8_t senderAccId[20],
                                            size_t &accountFieldOffsetOut) {
  std::vector<uint8_t> buf;
  buf.reserve(160);
  writeUInt16Field(buf, 0x12, 0);             // TransactionType = Payment (1,2)
  writeUInt32Field(buf, 0x22, 0);             // Flags = 0             (2,2)
  writeUInt32Field(buf, 0x24, s_seq);         // Sequence              (2,4)
  if (s_isIssued) {
    writeIssuedAmountField(buf, 0x61, s_exp, s_mantissa, s_currency, s_issuerAccId);  // (6,1)
  } else {
    writeAmountField(buf, 0x61, s_amount);      // Amount                (6,1)
  }
  writeAmountField(buf, 0x68, s_fee);         // Fee                   (6,8)
  writeBlobField  (buf, 0x73, pubkey, 33);    // SigningPubKey         (7,3)
  accountFieldOffsetOut = buf.size();
  writeAccountField(buf, 0x81, senderAccId);  // Account               (8,1)
  writeAccountField(buf, 0x83, s_destAccId);  // Destination           (8,3)
  return buf;
}

// Build a TrustSet's canonical serialized fields for signing. Field order
// and every field code here (TransactionType=20; Flags=tfSetNoRipple=
// 0x00020000; LimitAmount at (6,3) — same issued-currency Amount encoding
// as a Payment's own Amount field, just field code 3 instead of 1; no
// Destination at all) were confirmed by decoding a real historical TrustSet
// transaction's raw bytes off mainnet (tx 396591937C9BF9FA194F4C63080B7827
// D04E7237A8CB8A1B0B8A25CEB70A4101), not assumed from documentation alone —
// same "verify against ground truth" rigor as every other tx builder in
// this codebase. tfSetNoRipple is the standard default for a plain
// token-holding trustline not meant to be used as a payment path, matching
// what that same real transaction used.
static std::vector<uint8_t> buildTrustSetForSigning(const uint8_t pubkey[33],
                                                     const uint8_t senderAccId[20],
                                                     size_t &accountFieldOffsetOut) {
  std::vector<uint8_t> buf;
  buf.reserve(120);
  writeUInt16Field(buf, 0x12, 20);            // TransactionType = TrustSet (1,2)
  writeUInt32Field(buf, 0x22, 0x00020000);    // Flags = tfSetNoRipple  (2,2)
  writeUInt32Field(buf, 0x24, s_seq);         // Sequence               (2,4)
  writeIssuedAmountField(buf, 0x63, s_exp, s_mantissa, s_currency, s_issuerAccId);  // LimitAmount (6,3)
  writeAmountField(buf, 0x68, s_fee);         // Fee                    (6,8)
  writeBlobField  (buf, 0x73, pubkey, 33);    // SigningPubKey          (7,3)
  accountFieldOffsetOut = buf.size();
  writeAccountField(buf, 0x81, senderAccId);  // Account                (8,1)
  return buf;
}

// Insert TxnSignature (7,4 = 0x74) immediately before Account (8,1 = 0x81),
// at `insertPos` — the exact offset buildForSigning() recorded right before
// it wrote the Account field. This used to be a hardcoded literal (66,
// derived from TransactionType(3)+Flags(5)+Sequence(5)+Amount(9)+Fee(9)+
// SigningPubKey(35)) that only stayed correct because a native-XRP Amount
// field is always 9 bytes; an issued-currency Amount field is 49 bytes
// (1 header + 48 body: encoded value + currency + issuer), which the old
// hardcoded offset didn't account for at all. A fixed offset (rather than
// scanning for 0x81) is still used here — scanning would be wrong, since
// that byte can appear anywhere in the 33-byte pubkey data (~12% collision
// probability) — it's just computed from the real bytes now instead of
// assumed.
static std::vector<uint8_t> buildSignedTx(const std::vector<uint8_t> &forSigning,
                                          size_t insertPos,
                                          const uint8_t *der, size_t derLen) {
  std::vector<uint8_t> out;
  out.reserve(forSigning.size() + 2 + derLen);
  out.insert(out.end(), forSigning.begin(), forSigning.begin() + insertPos);
  out.push_back(0x74);                            // TxnSignature header (7,4)
  out.push_back((uint8_t)derLen);                 // VL prefix
  out.insert(out.end(), der, der + derLen);
  out.insert(out.end(), forSigning.begin() + insertPos, forSigning.end());
  return out;
}

// SHA-512 half of (0x53545800 + fields) = signing digest.
static void computeSigningDigest(const std::vector<uint8_t> &forSigning,
                                  uint8_t digest[32]) {
  static const uint8_t PREFIX[4] = {0x53, 0x54, 0x58, 0x00};
  size_t msgLen = 4 + forSigning.size();
  uint8_t *msg = (uint8_t *)malloc(msgLen);
  if (!msg) { memset(digest, 0, 32); return; }
  memcpy(msg, PREFIX, 4);
  memcpy(msg + 4, forSigning.data(), forSigning.size());
  uint8_t sha512[64];
  sha512_Raw(msg, (uint32_t)msgLen, sha512);
  memcpy(digest, sha512, 32);  // first 32 bytes = SHA-512 half
  free(msg);
}

}  // namespace

// ============================================================================
// public API
// ============================================================================
namespace xrp {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return String("");

  HDPrivateKey root(m, String(passphrase ? passphrase : ""), &Mainnet);
  m = "";

  char path[40];
  snprintf(path, sizeof(path), "m/44h/144h/0h/0/%lu", (unsigned long)index);
  HDPrivateKey child = root.derive(path);
  PublicKey pub = child.publicKey();
  pub.compressed = true;

  uint8_t sec[33];
  if (pub.sec(sec, sizeof(sec)) != 33) return String("");

  uint8_t sha[32];
  sha256_Raw(sec, 33, sha);
  uint8_t accountId[20];
  ripemd160(sha, 32, accountId);

  uint8_t payload[21];
  payload[0] = 0x00;
  memcpy(payload + 1, accountId, 20);

  uint8_t h1[32], h2[32];
  sha256_Raw(payload, 21, h1);
  sha256_Raw(h1,      32, h2);

  uint8_t enc[25];
  memcpy(enc,      payload, 21);
  memcpy(enc + 21, h2,       4);
  return xrpBase58Check(enc, 25);
}

// Native XRP Payment: "XRP|acct|seq|amountDrops|feeDrops|destAccountIdHex"
static bool loadNativeTx(const String &line) {
  String parts[6];
  int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 6; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i);
      start = i + 1;
    }
  }
  if (np < 6 || parts[0] != "XRP") return false;

  s_acct   = (uint32_t)parts[1].toInt();
  s_seq    = (uint32_t)parts[2].toInt();
  s_amount = (uint64_t)strtoull(parts[3].c_str(), nullptr, 10);
  s_fee    = (uint64_t)strtoull(parts[4].c_str(), nullptr, 10);
  if (!hex20(parts[5], s_destAccId)) return false;

  s_isIssued = false;
  s_loaded = true;
  return true;
}

// Issued-currency Payment (e.g. RLUSD): "XRPT|acct|seq|exp|mantissa|
// currencyHex|issuerAccountIdHex|feeDrops|destAccountIdHex". `exp`/
// `mantissa` are already-normalized (the app does the decimal-to-
// exponent/mantissa canonicalization) — firmware just bit-packs them, see
// writeIssuedAmountField()'s own doc for the exact encoding.
static bool loadIssuedTx(const String &line) {
  String parts[9];
  int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 9; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i);
      start = i + 1;
    }
  }
  if (np < 9 || parts[0] != "XRPT") return false;

  s_acct     = (uint32_t)parts[1].toInt();
  s_seq      = (uint32_t)parts[2].toInt();
  s_exp      = (int32_t)parts[3].toInt();
  s_mantissa = (uint64_t)strtoull(parts[4].c_str(), nullptr, 10);
  if (!hex20(parts[5], s_currency)) return false;
  if (!hex20(parts[6], s_issuerAccId)) return false;
  s_fee      = (uint64_t)strtoull(parts[7].c_str(), nullptr, 10);
  if (!hex20(parts[8], s_destAccId)) return false;

  s_isIssued = true;
  s_loaded = true;
  return true;
}

// TrustSet: "XRPTRUST|acct|seq|exp|mantissa|currencyHex|issuerAccountIdHex|
// feeDrops" — 8 fields, no destination (TrustSet has none; the
// counterparty is the issuer inside LimitAmount itself).
static bool loadTrustSetTx(const String &line) {
  String parts[8];
  int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 8; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i);
      start = i + 1;
    }
  }
  if (np < 8 || parts[0] != "XRPTRUST") return false;

  s_acct     = (uint32_t)parts[1].toInt();
  s_seq      = (uint32_t)parts[2].toInt();
  s_exp      = (int32_t)parts[3].toInt();
  s_mantissa = (uint64_t)strtoull(parts[4].c_str(), nullptr, 10);
  if (!hex20(parts[5], s_currency)) return false;
  if (!hex20(parts[6], s_issuerAccId)) return false;
  s_fee      = (uint64_t)strtoull(parts[7].c_str(), nullptr, 10);

  s_isTrustSet = true;
  s_loaded = true;
  return true;
}

bool loadTx(const String &line) {
  clearTx();
  int sep = line.indexOf('|');
  String tag = sep >= 0 ? line.substring(0, sep) : line;
  if (tag == "XRPTRUST") return loadTrustSetTx(line);
  if (tag == "XRPT") return loadIssuedTx(line);
  return loadNativeTx(line);
}

bool isIssuedTx() { return s_isIssued; }
bool isTrustSetTx() { return s_isTrustSet; }

String txHashHex() {
  if (!s_loaded) return String("?");
  // Show first 4 bytes of destination AccountID as an 8-char hex preview.
  char buf[9];
  for (int i = 0; i < 4; i++) {
    buf[2 * i]     = HEXCH[s_destAccId[i] >> 4];
    buf[2 * i + 1] = HEXCH[s_destAccId[i] & 0x0F];
  }
  buf[8] = '\0';
  return String(buf);
}

String signTx(const uint8_t *entropy, size_t entLen, const char *passphrase) {
  if (!s_loaded) return String("");

  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return String("");

  HDPrivateKey root(m, String(passphrase ? passphrase : ""), &Mainnet);
  m = "";

  char path[40];
  snprintf(path, sizeof(path), "m/44h/144h/0h/0/%lu", (unsigned long)s_acct);
  HDPrivateKey child = root.derive(path);

  // Derive compressed public key (33 bytes).
  PublicKey pub = child.publicKey();
  pub.compressed = true;
  uint8_t pubkey[33];
  if (pub.sec(pubkey, sizeof(pubkey)) != 33) return String("");

  // Sender AccountID = RIPEMD160(SHA256(compressedPubKey)).
  uint8_t sha[32], senderAccId[20];
  sha256_Raw(pubkey, 33, sha);
  ripemd160(sha, 32, senderAccId);

  // Build canonical tx bytes for signing (includes SigningPubKey, no TxnSignature).
  size_t accountFieldOffset = 0;
  std::vector<uint8_t> forSigning = s_isTrustSet
      ? buildTrustSetForSigning(pubkey, senderAccId, accountFieldOffset)
      : buildForSigning(pubkey, senderAccId, accountFieldOffset);

  // Compute SHA-512 half of signing prefix + tx bytes.
  uint8_t digest[32];
  computeSigningDigest(forSigning, digest);

  // Sign with secp256k1.
  Signature sig = child.sign(digest);
  uint8_t der[73];
  size_t derLen = sig.der(der, sizeof(der));
  if (derLen == 0) return String("");

  // Produce complete signed transaction.
  std::vector<uint8_t> signedTx = buildSignedTx(forSigning, accountFieldOffset, der, derLen);

  // Return as lowercase hex.
  String out;
  out.reserve(signedTx.size() * 2);
  for (size_t i = 0; i < signedTx.size(); i++) {
    out += HEXCH[signedTx[i] >> 4];
    out += HEXCH[signedTx[i] & 0x0F];
  }
  return out;
}

void clearTx() {
  s_loaded   = false;
  s_isIssued = false;
  s_isTrustSet = false;
  s_acct     = 0;
  s_seq      = 0;
  s_amount   = 0;
  s_exp      = 0;
  s_mantissa = 0;
  memset(s_currency, 0, sizeof(s_currency));
  memset(s_issuerAccId, 0, sizeof(s_issuerAccId));
  s_fee      = 0;
  memset(s_destAccId, 0, sizeof(s_destAccId));
}

}  // namespace xrp
