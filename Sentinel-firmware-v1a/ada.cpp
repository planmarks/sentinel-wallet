#include "ada.h"
#include "wallet.h"

#include <vector>
#include <string.h>

extern "C" {
#include "blake2.h"
void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen,
                        uint32_t iterations, uint8_t *key, int keylen);
void ubtc_hmac_sha512(const uint8_t *key, uint32_t keylen,
                      const uint8_t *msg, uint32_t msglen, uint8_t *out);
void ed25519_scalarmult_base(unsigned char *out, const unsigned char *scalar);
void ed25519_sign_extended32(unsigned char *sig, const unsigned char *kL,
                             const unsigned char *kR, const unsigned char *A,
                             const unsigned char *m);
}

namespace {

#define HARD(x) ((uint32_t)(x) | 0x80000000UL)

// Icarus master key: 96 bytes (kL||kR||chainCode), kL clamped.
void icarusMaster(const uint8_t *entropy, size_t entLen, uint8_t xprv[96]) {
  pbkdf2_hmac_sha512((const uint8_t *)"", 0, entropy, (int)entLen, 4096, xprv, 96);
  xprv[0]  &= 0xF8;
  xprv[31] &= 0x1F;
  xprv[31] |= 0x40;
}

// out = kL + 8*ZL  (ZL = Z[0:28], all little-endian, mod 2^256)
void add8ZL(uint8_t out[32], const uint8_t Z[64], const uint8_t kL[32]) {
  uint8_t r[32]; memset(r, 0, 32);
  uint32_t carry = 0;
  for (int i = 0; i < 28; i++) {
    uint32_t v = (uint32_t)Z[i] * 8 + carry;
    r[i] = (uint8_t)(v & 0xff);
    carry = v >> 8;
  }
  r[28] = (uint8_t)(carry & 0xff);           // 8*ZL fits in 29 bytes
  uint32_t c = 0;
  for (int i = 0; i < 32; i++) {
    uint32_t v = (uint32_t)r[i] + kL[i] + c;
    out[i] = (uint8_t)(v & 0xff);
    c = v >> 8;
  }
}

// out = ZR + kR  (mod 2^256, little-endian)
void addKR(uint8_t out[32], const uint8_t ZR[32], const uint8_t kR[32]) {
  uint32_t c = 0;
  for (int i = 0; i < 32; i++) {
    uint32_t v = (uint32_t)ZR[i] + kR[i] + c;
    out[i] = (uint8_t)(v & 0xff);
    c = v >> 8;
  }
}

// BIP32-Ed25519 child derivation (Cardano). index hardened iff top bit set.
void deriveChild(const uint8_t parent[96], uint32_t index, uint8_t child[96]) {
  const uint8_t *kL = parent, *kR = parent + 32, *cc = parent + 64;
  uint8_t Z[64], C[64];
  uint8_t iLE[4] = { (uint8_t)index, (uint8_t)(index >> 8),
                     (uint8_t)(index >> 16), (uint8_t)(index >> 24) };  // little-endian

  if (index & 0x80000000UL) {
    uint8_t d[1 + 64 + 4];
    d[0] = 0x00; memcpy(d + 1, kL, 32); memcpy(d + 33, kR, 32); memcpy(d + 65, iLE, 4);
    ubtc_hmac_sha512(cc, 32, d, sizeof(d), Z);
    d[0] = 0x01;
    ubtc_hmac_sha512(cc, 32, d, sizeof(d), C);
  } else {
    uint8_t A[32]; ed25519_scalarmult_base(A, kL);
    uint8_t d[1 + 32 + 4];
    d[0] = 0x02; memcpy(d + 1, A, 32); memcpy(d + 33, iLE, 4);
    ubtc_hmac_sha512(cc, 32, d, sizeof(d), Z);
    d[0] = 0x03;
    ubtc_hmac_sha512(cc, 32, d, sizeof(d), C);
  }

  add8ZL(child, Z, kL);
  addKR(child + 32, Z + 32, kR);
  memcpy(child + 64, C + 32, 32);
}

void deriveExtended(const uint8_t master[96], const uint32_t *path, size_t n, uint8_t out[96]) {
  uint8_t cur[96]; memcpy(cur, master, 96);
  for (size_t i = 0; i < n; i++) {
    uint8_t nxt[96];
    deriveChild(cur, path[i], nxt);
    memcpy(cur, nxt, 96);
  }
  memcpy(out, cur, 96);
  memset(cur, 0, sizeof(cur));
}

// ---- bech32 (Cardano uses standard bech32, no 90-char limit) ----
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

size_t convertbits(const uint8_t *in, size_t inlen, uint8_t *out) {
  uint32_t acc = 0; int bits = 0; size_t o = 0;
  for (size_t i = 0; i < inlen; i++) {
    acc = (acc << 8) | in[i]; bits += 8;
    while (bits >= 5) { out[o++] = (acc >> (bits - 5)) & 31; bits -= 5; }
  }
  if (bits > 0) out[o++] = (acc << (5 - bits)) & 31;
  return o;
}

// Derive the payment extended key m/1852'/1815'/index'/0/0 (96 bytes).
// index = account index (Ledger/CIP-1852 convention).
void paymentExtKey(const uint8_t *entropy, size_t entLen, uint32_t index, uint8_t out[96]) {
  uint8_t master[96];
  icarusMaster(entropy, entLen, master);
  uint32_t path[5] = { HARD(1852), HARD(1815), HARD(index), 0, 0 };
  deriveExtended(master, path, 5, out);
  memset(master, 0, sizeof(master));
}

// Derive the stake extended key m/1852'/1815'/index'/2/0 (96 bytes) — the
// same path already used for stake-address derivation in address() below,
// factored out here so signTxStake() can reuse it for delegation-certificate
// witnesses.
void stakeExtKey(const uint8_t *entropy, size_t entLen, uint32_t index, uint8_t out[96]) {
  uint8_t master[96];
  icarusMaster(entropy, entLen, master);
  uint32_t path[5] = { HARD(1852), HARD(1815), HARD(index), 2, 0 };
  deriveExtended(master, path, 5, out);
  memset(master, 0, sizeof(master));
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
String toHex(const uint8_t *d, size_t n) {
  static const char *H = "0123456789abcdef";
  String s;
  for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 0xf]; }
  return s;
}

// --- pending tx state ---
std::vector<uint8_t> s_txBody;
uint32_t s_index  = 0;
uint8_t  s_hash[32];
bool     s_loaded = false;
bool     s_needsStake = false;

String bech32Encode(const char *hrp, const uint8_t *data5, size_t d5) {
  static const char *CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  size_t hlen = strlen(hrp);
  uint8_t values[192];
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

}  // namespace

namespace ada {

String address(const uint8_t *entropy, size_t entLen, const char * /*passphrase*/,
               uint32_t index) {
  uint8_t master[96];
  icarusMaster(entropy, entLen, master);      // Icarus ignores the BIP39 passphrase

  // payment key: m/1852'/1815'/index'/0/0  (index = account, Ledger convention)
  uint32_t payPath[5] = { HARD(1852), HARD(1815), HARD(index), 0, 0 };
  uint8_t payX[96]; deriveExtended(master, payPath, 5, payX);
  uint8_t payPub[32]; ed25519_scalarmult_base(payPub, payX);   // [kL]B

  // stake key: m/1852'/1815'/index'/2/0
  uint32_t stkPath[5] = { HARD(1852), HARD(1815), HARD(index), 2, 0 };
  uint8_t stkX[96]; deriveExtended(master, stkPath, 5, stkX);
  uint8_t stkPub[32]; ed25519_scalarmult_base(stkPub, stkX);

  memset(master, 0, sizeof(master));
  memset(payX, 0, sizeof(payX));
  memset(stkX, 0, sizeof(stkX));

  uint8_t payHash[28], stkHash[28];
  blake2b(payHash, 28, payPub, 32, nullptr, 0);
  blake2b(stkHash, 28, stkPub, 32, nullptr, 0);

  // Shelley base address: header || paymentKeyHash(28) || stakeKeyHash(28).
  // header = (type 0 << 4) | networkId ; network 1 = mainnet — mainnet only,
  // this device line never supports testnet (removed 2026-08-09).
  uint8_t addr[57];
  addr[0] = 0x01;
  memcpy(addr + 1, payHash, 28);
  memcpy(addr + 29, stkHash, 28);

  uint8_t data5[128];
  size_t d5 = convertbits(addr, 57, data5);
  return bech32Encode("addr", data5, d5);
}

void clearTx() {
  s_txBody.clear();
  s_loaded = false;
  s_index = 0;
  s_needsStake = false;
}

bool loadTx(const String &line) {
  clearTx();
  int p1 = line.indexOf('|');
  if (p1 < 0) return false;
  int p2 = line.indexOf('|', p1 + 1);
  if (p2 < 0) return false;
  if (line.substring(0, p1) != "ADA") return false;
  s_index = (uint32_t)line.substring(p1 + 1, p2).toInt();

  // Optional 4th field ("STAKE") flags a tx whose witness set needs a
  // second, stake-key witness — everything after it (there is nothing else
  // today) is still part of this same field, so a plain 3-field line (hex
  // with no further '|') is unaffected either way.
  int p3 = line.indexOf('|', p2 + 1);
  String hex = (p3 < 0) ? line.substring(p2 + 1) : line.substring(p2 + 1, p3);
  if (p3 >= 0 && line.substring(p3 + 1) == "STAKE") s_needsStake = true;

  int L = (int)hex.length();
  if (L < 2 || (L & 1)) return false;
  s_txBody.reserve(L / 2);
  for (int i = 0; i < L; i += 2) {
    int hi = hexVal(hex[i]), lo = hexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) { clearTx(); return false; }
    s_txBody.push_back((uint8_t)((hi << 4) | lo));
  }
  blake2b(s_hash, 32, s_txBody.data(), s_txBody.size(), nullptr, 0);   // tx body hash
  s_loaded = true;
  return true;
}

String txHashHex() { return s_loaded ? toHex(s_hash, 8) : String(""); }
bool   needsStakeWitness() { return s_loaded && s_needsStake; }

// Signs s_hash with whichever extended key `deriveKey` produces, returning
// vkeyHex(64) || sigHex(128). Shared by signTx()/signTxStake() — the two
// differ only in which CIP-1852 path they derive.
String signWith(void (*deriveKey)(const uint8_t *, size_t, uint32_t, uint8_t[96]),
                 const uint8_t *entropy, size_t entLen) {
  uint8_t x[96];
  deriveKey(entropy, entLen, s_index, x);
  uint8_t A[32];
  ed25519_scalarmult_base(A, x);                // vkey = [kL]B
  uint8_t sig[64];
  ed25519_sign_extended32(sig, x, x + 32, A, s_hash);
  memset(x, 0, sizeof(x));
  return toHex(A, 32) + toHex(sig, 64);         // vkey || signature
}

String signTx(const uint8_t *entropy, size_t entLen, const char * /*passphrase*/) {
  if (!s_loaded) return String("");
  return signWith(paymentExtKey, entropy, entLen);   // Icarus ignores passphrase
}

// Signs the *currently loaded* tx hash with the stake key instead of the
// payment key — a delegation certificate's witness must come from the stake
// credential it names (CIP-1852 m/1852'/1815'/index'/2/0), never the payment
// key. Must be called before clearTx(); the app requests this immediately
// after signTx() for any ADA tx that carries a delegation certificate (a
// stake_delegation cert always needs this witness; a bare
// stake_registration cert needs none, but the app always asks for a stake
// witness whenever it built a delegation cert, so this is unconditional
// here — deciding *whether* to ask is the app's job, not firmware's).
String signTxStake(const uint8_t *entropy, size_t entLen, const char * /*passphrase*/) {
  if (!s_loaded) return String("");
  return signWith(stakeExtKey, entropy, entLen);
}

}  // namespace ada
