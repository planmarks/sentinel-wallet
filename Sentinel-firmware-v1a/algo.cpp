#include "algo.h"
#include "wallet.h"
#include "slip10.h"
#include "ed25519.h"

#include <string.h>

// Mirrors utility/trezor/sha2.h's SHA512_CTX layout exactly (not included
// directly — this file follows the same extern "C" forward-declare pattern
// eth.cpp/apt.cpp/near.cpp already use for other vendored trezor-crypto
// primitives, rather than pulling in the nested vendor header path).
typedef struct _SHA512_CTX {
  uint64_t state[8];
  uint64_t bitcount[2];
  uint64_t buffer[16];
} SHA512_CTX;

extern "C" {
  void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                        uint8_t seed[64], void (*cb)(uint32_t, uint32_t));
  void sha512_Init(SHA512_CTX *context);
  void sha512_Update(SHA512_CTX *context, const uint8_t *data, size_t len);
  void sha512_Final(SHA512_CTX *context, uint8_t digest[64]);
}

namespace {

static const char HEXCH[] = "0123456789abcdef";
static const char B32CH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const size_t MAX_PAYLOAD = 400;  // "TX" + canonical-msgpack for a simple pay txn

static bool     s_loaded     = false;
static uint32_t s_acct       = 0;
static uint8_t  s_payload[MAX_PAYLOAD];
static size_t   s_payloadLen = 0;

// SHA-512/256 IV (FIPS 180-4 §5.3.6) — distinct from plain SHA-512's IV.
// Verified against Go's crypto/internal/fips140/sha512 source constants.
static const uint64_t SHA512_256_IV[8] = {
  0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
  0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL,
};

void sha512_256(const uint8_t *data, size_t len, uint8_t digest32[32]) {
  SHA512_CTX ctx;
  sha512_Init(&ctx);
  memcpy(ctx.state, SHA512_256_IV, sizeof(SHA512_256_IV));
  sha512_Update(&ctx, data, len);
  uint8_t full[64];
  sha512_Final(&ctx, full);
  memcpy(digest32, full, 32);
}

// RFC4648 base32, no padding.
String base32Encode(const uint8_t *data, size_t len) {
  String out;
  out.reserve(((len * 8 + 4) / 5) + 1);
  int bits = 0;
  uint32_t buf = 0;
  for (size_t i = 0; i < len; i++) {
    buf = (buf << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32CH[(buf >> bits) & 0x1F];
    }
  }
  if (bits > 0) {
    out += B32CH[(buf << (5 - bits)) & 0x1F];
  }
  return out;
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool derivePub(const uint8_t *entropy, size_t entLen, const char *passphrase,
               uint32_t index, uint8_t priv[32], uint8_t pub[32]) {
  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return false;
  uint8_t seed[64];
  mnemonic_to_seed(m.c_str(), passphrase ? passphrase : "", seed, nullptr);
  m = "";
  uint32_t path[5] = { 44, 283, 0, 0, index };  // SLIP-10 hardens each element
  bool ok = slip10::deriveEd25519(seed, path, 5, priv);
  memset(seed, 0, sizeof(seed));
  if (!ok) return false;
  ed25519::publicKey(priv, pub);
  return true;
}

}  // namespace

namespace algo {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  uint8_t priv[32], pub[32];
  if (!derivePub(entropy, entLen, passphrase, index, priv, pub)) return String("");
  memset(priv, 0, sizeof(priv));

  uint8_t checksum[32];
  sha512_256(pub, 32, checksum);

  uint8_t payload[36];
  memcpy(payload, pub, 32);
  memcpy(payload + 32, checksum + 28, 4);  // last 4 bytes of the checksum

  return base32Encode(payload, sizeof(payload));
}

String pubKeyHex(const uint8_t *entropy, size_t entLen,
                 const char *passphrase, uint32_t index) {
  uint8_t priv[32], pub[32];
  if (!derivePub(entropy, entLen, passphrase, index, priv, pub)) return String("");
  memset(priv, 0, sizeof(priv));

  String out; out.reserve(64);
  for (int i = 0; i < 32; i++) { out += HEXCH[pub[i] >> 4]; out += HEXCH[pub[i] & 0x0F]; }
  return out;
}

bool loadTx(const String &line) {
  clearTx();
  // ALGO|acct|payloadHex
  String parts[3]; int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 3; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i); start = i + 1;
    }
  }
  if (np < 3 || parts[0] != "ALGO") return false;
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
  uint8_t priv[32], pub[32];
  if (!derivePub(entropy, entLen, passphrase, s_acct, priv, pub)) return String("");

  uint8_t sig[64];
  ed25519::sign(priv, s_payload, s_payloadLen, sig);
  memset(priv, 0, sizeof(priv));

  String out; out.reserve(128);
  for (int i = 0; i < 64; i++) { out += HEXCH[sig[i] >> 4]; out += HEXCH[sig[i] & 0x0F]; }
  return out;
}

void clearTx() {
  s_loaded     = false;
  s_acct       = 0;
  s_payloadLen = 0;
  memset(s_payload, 0, sizeof(s_payload));
}

}  // namespace algo
