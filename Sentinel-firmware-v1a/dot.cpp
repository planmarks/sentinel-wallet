#include "dot.h"
#include "wallet.h"
#include "slip10.h"
#include "ed25519.h"
#include "blake2.h"

#include <string.h>

extern "C" {
  void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                        uint8_t seed[64], void (*cb)(uint32_t, uint32_t));
  bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
}

namespace {

static const char    HEXCH[]      = "0123456789abcdef";
static const uint8_t SS58_PRE[]   = { 'S', 'S', '5', '8', 'P', 'R', 'E' };
static const uint8_t DOT_NETWORK  = 0x00;  // Polkadot mainnet

static const size_t MAX_PAYLOAD = 512;

static bool     s_loaded     = false;
static uint32_t s_acct       = 0;
static uint8_t  s_payload[MAX_PAYLOAD];
static size_t   s_payloadLen = 0;

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
  uint32_t path[3] = { 44, 354, index };  // SLIP-10 hardens each element
  bool ok = slip10::deriveEd25519(seed, path, 3, priv);
  memset(seed, 0, sizeof(seed));
  if (!ok) return false;
  ed25519::publicKey(priv, pub);
  return true;
}

}  // namespace

namespace dot {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  uint8_t priv[32], pub[32];
  if (!derivePub(entropy, entLen, passphrase, index, priv, pub)) return String("");
  memset(priv, 0, sizeof(priv));

  // SS58 checksum: Blake2b-512("SS58PRE" || network_byte || pubkey)[0:2]
  uint8_t input[7 + 1 + 32];
  memcpy(input, SS58_PRE, 7);
  input[7] = DOT_NETWORK;
  memcpy(input + 8, pub, 32);

  uint8_t hash[64];
  blake2b(hash, sizeof(hash), input, sizeof(input), nullptr, 0);

  // Payload to base58: [network_byte || pubkey(32) || checksum(2)] = 35 bytes
  uint8_t raw[35];
  raw[0] = DOT_NETWORK;
  memcpy(raw + 1, pub, 32);
  raw[33] = hash[0];
  raw[34] = hash[1];

  char b58[64];
  size_t b58sz = sizeof(b58);
  if (!b58enc(b58, &b58sz, raw, sizeof(raw))) return String("");
  return String(b58);
}

bool loadTx(const String &line) {
  clearTx();
  // DOT|acct|payloadHex
  String parts[3]; int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 3; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i); start = i + 1;
    }
  }
  if (np < 3 || parts[0] != "DOT") return false;
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

  // Substrate spec: payload > 256 bytes → sign Blake2b-256 hash instead
  uint8_t toSign[256];
  size_t  toSignLen;
  if (s_payloadLen > 256) {
    blake2b(toSign, 32, s_payload, s_payloadLen, nullptr, 0);
    toSignLen = 32;
  } else {
    memcpy(toSign, s_payload, s_payloadLen);
    toSignLen = s_payloadLen;
  }

  uint8_t sig[64];
  ed25519::sign(priv, toSign, toSignLen, sig);
  memset(priv, 0, sizeof(priv));
  memset(toSign, 0, sizeof(toSign));

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

}  // namespace dot
