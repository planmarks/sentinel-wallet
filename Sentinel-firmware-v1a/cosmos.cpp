#include "cosmos.h"
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

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int hexToBytes(const String &h, uint8_t *out, size_t maxLen) {
  int start = 0, L = (int)h.length();
  if (L >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) start = 2;
  int nhex = L - start;
  if (nhex <= 0 || (nhex & 1)) return -1;
  int oi = 0, idx = start;
  while (nhex > 0) {
    int hi = hexVal(h[idx++]), lo = hexVal(h[idx++]);
    if (hi < 0 || lo < 0) return -1;
    if ((size_t)oi >= maxLen) return -1;
    out[oi++] = (uint8_t)((hi << 4) | lo);
    nhex -= 2;
  }
  return oi;
}

// ---- bech32 (BIP173), used for the "cosmos" HRP -----------------------------
uint32_t bech32Polymod(const uint8_t *v, size_t len) {
  static const uint32_t GEN[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
  uint32_t chk = 1;
  for (size_t i = 0; i < len; i++) {
    uint8_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v[i];
    for (int j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= GEN[j];
  }
  return chk;
}

// Regroup 8-bit bytes into 5-bit groups (pad with zero bits).
size_t convertbits(const uint8_t *in, size_t inlen, uint8_t *out) {
  uint32_t acc = 0; int bits = 0; size_t o = 0;
  for (size_t i = 0; i < inlen; i++) {
    acc = (acc << 8) | in[i]; bits += 8;
    while (bits >= 5) { out[o++] = (acc >> (bits - 5)) & 31; bits -= 5; }
  }
  if (bits > 0) out[o++] = (acc << (5 - bits)) & 31;
  return o;
}

String bech32Encode(const char *hrp, const uint8_t *data5, size_t d5) {
  static const char *CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  size_t hlen = strlen(hrp);
  uint8_t values[128];
  size_t p = 0;
  for (size_t i = 0; i < hlen; i++) values[p++] = hrp[i] >> 5;
  values[p++] = 0;
  for (size_t i = 0; i < hlen; i++) values[p++] = hrp[i] & 31;
  for (size_t i = 0; i < d5; i++) values[p++] = data5[i];
  for (int i = 0; i < 6; i++) values[p++] = 0;
  uint32_t polymod = bech32Polymod(values, p) ^ 1;

  String out = String(hrp) + "1";
  for (size_t i = 0; i < d5; i++) out += CH[data5[i]];
  for (int i = 0; i < 6; i++) out += CH[(polymod >> (5 * (5 - i))) & 31];
  return out;
}

// ---- pending tx state -------------------------------------------------------
static bool     s_loaded = false;
static uint32_t s_acct   = 0;
static uint8_t  s_digest[32];   // SHA256(SignDoc)

}  // namespace

namespace cosmos {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index, const char *hrp) {
  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return String("");

  HDPrivateKey root(m, String(passphrase ? passphrase : ""), &Mainnet);
  m = "";

  char path[40];
  snprintf(path, sizeof(path), "m/44h/118h/0h/0/%lu", (unsigned long)index);
  HDPrivateKey child = root.derive(path);
  PublicKey pub = child.publicKey();
  pub.compressed = true;

  uint8_t sec[33];
  if (pub.sec(sec, sizeof(sec)) != 33) return String("");

  uint8_t sha[32];  sha256_Raw(sec, 33, sha);
  uint8_t acc[20];  ripemd160(sha, 32, acc);

  uint8_t d5[40];
  size_t n5 = convertbits(acc, 20, d5);
  return bech32Encode(hrp, d5, n5);
}

bool loadTx(const String &line, const char *ticker) {
  clearTx();
  // TICKER|acct|signDocHex
  String parts[3]; int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 3; i++) {
    if (i == (int)line.length() || line[i] == '|') { parts[np++] = line.substring(start, i); start = i + 1; }
  }
  if (np < 3 || parts[0] != ticker) return false;
  s_acct = (uint32_t)parts[1].toInt();

  static uint8_t body[4096];   // SignDoc bytes (transient — only hashed)
  int n = hexToBytes(parts[2], body, sizeof(body));
  if (n <= 0) return false;
  sha256_Raw(body, (uint32_t)n, s_digest);
  s_loaded = true;
  return true;
}

String txHashHex() {
  if (!s_loaded) return String("?");
  char buf[9];
  for (int i = 0; i < 4; i++) {
    buf[2 * i]     = HEXCH[s_digest[i] >> 4];
    buf[2 * i + 1] = HEXCH[s_digest[i] & 0x0F];
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
  snprintf(path, sizeof(path), "m/44h/118h/0h/0/%lu", (unsigned long)s_acct);
  HDPrivateKey child = root.derive(path);

  Signature sig = child.sign(s_digest);   // low-s RFC6979
  uint8_t rs[65]; sig.bin(rs, sizeof(rs));  // r[32] s[32] index

  // Cosmos signatures are 64-byte compact r||s (no recovery byte).
  String out; out.reserve(128);
  for (int i = 0; i < 64; i++) { out += HEXCH[rs[i] >> 4]; out += HEXCH[rs[i] & 0x0F]; }
  return out;
}

void clearTx() {
  s_loaded = false;
  s_acct   = 0;
  memset(s_digest, 0, sizeof(s_digest));
}

}  // namespace cosmos
