#include "store.h"
#include "config.h"
#include "wallet.h"

#include <Preferences.h>
#include <string.h>
#include "esp_random.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

namespace {
const uint8_t STORE_VER = 1;
const size_t  SALT_LEN  = 16;
const size_t  IV_LEN    = 12;
const size_t  TAG_LEN   = 16;
const size_t  KEY_LEN   = 32;   // AES-256
const size_t  MAX_ENT   = 32;   // 24-word entropy
const size_t  MAX_PLAIN = 32 + 64;  // entropy + passphrase (see MAX_PASSPHRASE)
const char   *AAD       = "coldwallet/v1";

bool deriveKey(const char *pin, const uint8_t *salt, uint8_t *key) {
  int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(
      MBEDTLS_MD_SHA256,
      (const unsigned char *)pin, strlen(pin),
      salt, SALT_LEN, PBKDF2_ITERS, KEY_LEN, key);
  return rc == 0;
}
}  // namespace

namespace store {

bool hasSeed() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return false;   // read-only
  bool has = p.isKey("ct");
  p.end();
  return has;
}

uint8_t triesRemaining() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return PIN_MAX_TRIES;
  uint8_t t = p.getUChar("tries", 0);
  p.end();
  if (t > PIN_MAX_TRIES) t = PIN_MAX_TRIES;
  return PIN_MAX_TRIES - t;
}

void wipe() {
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    p.clear();
    p.end();
  }
}

bool bleEnabled() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return false;
  uint8_t b = p.getUChar("ble", 0);   // default: OFF
  p.end();
  return b != 0;
}

void setBleEnabled(bool on) {
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    p.putUChar("ble", on ? 1 : 0);
    p.end();
  }
}

uint8_t coin() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return COIN_BTC;
  uint8_t c = p.getUChar("coin", COIN_BTC);
  p.end();
  return c;
}

void setCoin(uint8_t c) {
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    p.putUChar("coin", c);
    p.end();
  }
}

uint8_t autoLockMinutes() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return 3;   // default: 3 minutes
  uint8_t m = p.getUChar("alockmin", 3);
  p.end();
  return m;
}

void setAutoLockMinutes(uint8_t minutes) {
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    p.putUChar("alockmin", minutes);
    p.end();
  }
}

uint8_t language() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return 0;   // default: English
  uint8_t l = p.getUChar("lang", 0);
  p.end();
  return l;
}

void setLanguage(uint8_t idx) {
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    p.putUChar("lang", idx);
    p.end();
  }
}

void coinMaskBytes(uint8_t *out) {
  memset(out, 0, COIN_MASK_BYTES);
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return;
  p.getBytes("cmask2", out, COIN_MASK_BYTES);
  p.end();
}

void activateCoin(uint8_t c) {
  size_t byteIdx = c / 8;
  if (byteIdx >= COIN_MASK_BYTES) return;
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    uint8_t buf[COIN_MASK_BYTES] = {};
    p.getBytes("cmask2", buf, COIN_MASK_BYTES);
    buf[byteIdx] |= (uint8_t)(1u << (c % 8));
    p.putBytes("cmask2", buf, COIN_MASK_BYTES);
    p.end();
  }
}

void deactivateCoin(uint8_t c) {
  size_t byteIdx = c / 8;
  if (byteIdx >= COIN_MASK_BYTES) return;
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    uint8_t buf[COIN_MASK_BYTES] = {};
    p.getBytes("cmask2", buf, COIN_MASK_BYTES);
    buf[byteIdx] &= (uint8_t)~(1u << (c % 8));
    p.putBytes("cmask2", buf, COIN_MASK_BYTES);
    p.end();
  }
}

bool isCoinActive(uint8_t c) {
  size_t byteIdx = c / 8;
  if (byteIdx >= COIN_MASK_BYTES) return false;
  uint8_t buf[COIN_MASK_BYTES];
  coinMaskBytes(buf);
  return (buf[byteIdx] >> (c % 8)) & 1u;
}

bool anyCoinActive() {
  uint8_t buf[COIN_MASK_BYTES];
  coinMaskBytes(buf);
  for (size_t i = 0; i < COIN_MASK_BYTES; i++) {
    if (buf[i]) return true;
  }
  return false;
}

bool isBlindSignAllowed(uint8_t c) {
  size_t byteIdx = c / 8;
  if (byteIdx >= COIN_MASK_BYTES) return false;
  uint8_t buf[COIN_MASK_BYTES] = {};
  Preferences p;
  if (p.begin(NVS_NAMESPACE, true)) {
    p.getBytes("bsmask", buf, COIN_MASK_BYTES);
    p.end();
  }
  return (buf[byteIdx] >> (c % 8)) & 1u;
}

void setBlindSignAllowed(uint8_t c, bool allowed) {
  size_t byteIdx = c / 8;
  if (byteIdx >= COIN_MASK_BYTES) return;
  Preferences p;
  if (p.begin(NVS_NAMESPACE, false)) {
    uint8_t buf[COIN_MASK_BYTES] = {};
    p.getBytes("bsmask", buf, COIN_MASK_BYTES);
    if (allowed) buf[byteIdx] |= (uint8_t)(1u << (c % 8));
    else         buf[byteIdx] &= (uint8_t)~(1u << (c % 8));
    p.putBytes("bsmask", buf, COIN_MASK_BYTES);
    p.end();
  }
}

// ── Account bitmask (naccts v2) ──────────────────────────────────────────────
// Each byte is a bitmask of active BIP44 account indices for that coin.
// Bit N set = account index N is active.

static uint8_t _readNaccts(uint8_t c) {
  if (c >= COIN_COUNT) return 0;
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return 0;
  uint8_t buf[COIN_COUNT] = {};
  p.getBytes("naccts", buf, COIN_COUNT);
  p.end();
  return buf[c];
}

static void _writeNacctsBit(uint8_t c, uint8_t idx, bool set) {
  if (c >= COIN_COUNT || idx >= 8) return;
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return;
  uint8_t buf[COIN_COUNT] = {};
  p.getBytes("naccts", buf, COIN_COUNT);
  if (set) buf[c] |=  (1u << idx);
  else     buf[c] &= ~(1u << idx);
  p.putBytes("naccts", buf, COIN_COUNT);
  p.end();
}

uint8_t coinAccountMask(uint8_t c) { return _readNaccts(c); }

uint8_t coinAccountCount(uint8_t c) {
  return (uint8_t)__builtin_popcount(_readNaccts(c));
}

void setCoinAccountMask(uint8_t c, uint8_t mask) {
  if (c >= COIN_COUNT) return;
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return;
  uint8_t buf[COIN_COUNT] = {};
  p.getBytes("naccts", buf, COIN_COUNT);
  buf[c] = mask;
  p.putBytes("naccts", buf, COIN_COUNT);
  p.end();
}

void activateAccountBit(uint8_t c, uint8_t idx) {
  _writeNacctsBit(c, idx, true);
}

void deactivateAccountBit(uint8_t c, uint8_t idx) {
  _writeNacctsBit(c, idx, false);
}

// ── Account names (acn{coin}) ─────────────────────────────────────────────────
// Per-coin blob: 8 slots × 20 bytes each. Empty string = use default label.

static const uint8_t  ACCT_NAME_LEN   = 20;
static const uint8_t  ACCT_PER_COIN   = 8;
static const size_t   ACCT_NAMES_SIZE = ACCT_PER_COIN * ACCT_NAME_LEN; // 160

static void _acctNamesKey(uint8_t c, char* buf, size_t len) {
  snprintf(buf, len, "acn%u", (unsigned)c);
}

const char* accountName(uint8_t c, uint8_t idx) {
  static char nameBuf[ACCT_NAME_LEN];
  nameBuf[0] = '\0';
  if (c >= COIN_COUNT || idx >= ACCT_PER_COIN) return nameBuf;
  char key[8];
  _acctNamesKey(c, key, sizeof(key));
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return nameBuf;
  uint8_t blob[ACCT_NAMES_SIZE] = {};
  p.getBytes(key, blob, sizeof(blob));
  p.end();
  const char* src = reinterpret_cast<const char*>(blob + idx * ACCT_NAME_LEN);
  strncpy(nameBuf, src, ACCT_NAME_LEN - 1);
  nameBuf[ACCT_NAME_LEN - 1] = '\0';
  return nameBuf;
}

void setAccountName(uint8_t c, uint8_t idx, const char* name) {
  if (c >= COIN_COUNT || idx >= ACCT_PER_COIN || !name) return;
  char key[8];
  _acctNamesKey(c, key, sizeof(key));
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return;
  uint8_t blob[ACCT_NAMES_SIZE] = {};
  p.getBytes(key, blob, sizeof(blob));
  char* dest = reinterpret_cast<char*>(blob + idx * ACCT_NAME_LEN);
  strncpy(dest, name, ACCT_NAME_LEN - 1);
  dest[ACCT_NAME_LEN - 1] = '\0';
  p.putBytes(key, blob, sizeof(blob));
  p.end();
}

void clearAccountName(uint8_t c, uint8_t idx) {
  setAccountName(c, idx, "");
}

// ── NVS format migration ──────────────────────────────────────────────────────

void migrateIfNeeded() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return;
  uint8_t ver = p.getUChar("nv", 0);
  if (ver < 2) {
    // naccts used to store counts; now stores bitmasks — clear to avoid
    // misinterpretation. The app re-syncs bitmasks via ADDR_REQ on reconnect.
    uint8_t zeros[COIN_COUNT] = {};
    p.putBytes("naccts", zeros, COIN_COUNT);
    ver = 2;
  }
  if (ver < 3) {
    // Coin-active bitmask widened from a single uint32 ("cmask", capped at 32
    // coins) to a COIN_MASK_BYTES-byte array ("cmask2") since COIN_COUNT grew
    // past 32. Preserve whatever was already activated under the old key.
    if (p.isKey("cmask")) {
      uint32_t old = p.getUInt("cmask", 0);
      if (old != 0) {
        uint8_t buf[COIN_MASK_BYTES] = {};
        p.getBytes("cmask2", buf, COIN_MASK_BYTES);
        for (uint8_t i = 0; i < 32; i++) {
          if ((old >> i) & 1u) buf[i / 8] |= (uint8_t)(1u << (i % 8));
        }
        p.putBytes("cmask2", buf, COIN_MASK_BYTES);
      }
      p.remove("cmask");
    }
    ver = 3;
  }
  if (ver < 4) {
    // COIN_USDCTRX (id 18) was permanently removed 2026-08-01 (Circle
    // discontinued USDC on Tron) — id 18 itself is retired, never reused.
    // But a device that had already activated/created an account for it
    // before the removal is left with an orphaned active bit: nothing
    // recognizes id 18 anymore, so it falls through to every generic
    // default (shows as a bogus second "Bitcoin" on the home menu — see
    // coinDisplayName()'s default case — and fails to derive an address
    // when selected, since updateReceive() has no branch for it either).
    // Clear its activation bit, account bitmask, and any custom account
    // name so it fully disappears rather than lingering as a broken entry.
    uint8_t cmask[COIN_MASK_BYTES] = {};
    p.getBytes("cmask2", cmask, COIN_MASK_BYTES);
    cmask[18 / 8] &= (uint8_t)~(1u << (18 % 8));
    p.putBytes("cmask2", cmask, COIN_MASK_BYTES);

    uint8_t naccts[COIN_COUNT] = {};
    p.getBytes("naccts", naccts, COIN_COUNT);
    naccts[18] = 0;
    p.putBytes("naccts", naccts, COIN_COUNT);

    p.remove("acn18");
    ver = 4;
  }
  p.putUChar("nv", ver);
  p.end();
}

bool saveSeed(const uint8_t *entropy, size_t entLen, const char *passphrase, const char *pin) {
  if (!entropy || !pin || entLen == 0 || entLen > MAX_ENT) return false;
  size_t plen = passphrase ? strlen(passphrase) : 0;
  if (plen > MAX_PASSPHRASE) return false;
  const size_t total = entLen + plen;

  uint8_t rnd[SALT_LEN + IV_LEN];
  if (!wallet::generateEntropy(rnd, sizeof(rnd))) return false;

  uint8_t salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
  uint8_t plain[MAX_PLAIN], ct[MAX_PLAIN];
  memcpy(salt, rnd, SALT_LEN);
  memcpy(iv, rnd + SALT_LEN, IV_LEN);
  mbedtls_platform_zeroize(rnd, sizeof(rnd));

  // Plaintext = entropy || passphrase (both lengths stored separately).
  memcpy(plain, entropy, entLen);
  if (plen) memcpy(plain + entLen, passphrase, plen);

  bool ok = false;
  if (deriveKey(pin, salt, key)) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, KEY_LEN * 8) == 0 &&
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, total,
                                  iv, IV_LEN,
                                  (const unsigned char *)AAD, strlen(AAD),
                                  plain, ct, TAG_LEN, tag) == 0) {
      Preferences p;
      if (p.begin(NVS_NAMESPACE, false)) {
        p.putUChar("ver", STORE_VER);
        p.putBytes("salt", salt, SALT_LEN);
        p.putBytes("iv", iv, IV_LEN);
        p.putBytes("ct", ct, total);
        p.putBytes("tag", tag, TAG_LEN);
        p.putUChar("elen", (uint8_t)entLen);
        p.putUChar("plen", (uint8_t)plen);
        p.putUChar("tries", 0);
        p.end();
        ok = true;
      }
    }
    mbedtls_gcm_free(&gcm);
  }

  mbedtls_platform_zeroize(key, sizeof(key));
  mbedtls_platform_zeroize(plain, sizeof(plain));
  mbedtls_platform_zeroize(ct, sizeof(ct));
  mbedtls_platform_zeroize(tag, sizeof(tag));
  return ok;
}

LoadResult loadSeed(const char *pin, uint8_t *entropy, size_t *outLen,
                    char *passphrase, size_t passMax, uint8_t *triesLeft) {
  if (!pin || !entropy || !outLen) return LOAD_ERROR;
  if (passphrase && passMax) passphrase[0] = '\0';

  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return LOAD_ERROR;
  if (!p.isKey("ct")) { p.end(); return LOAD_EMPTY; }

  uint8_t tries = p.getUChar("tries", 0);
  if (tries >= PIN_MAX_TRIES) {
    p.end();
    wipe();
    if (triesLeft) *triesLeft = 0;
    return LOAD_WIPED;
  }

  // Persist the incremented counter BEFORE checking, so yanking power during an
  // attempt still burns the try (anti power-cycle brute force).
  const uint8_t attempt = tries + 1;
  p.putUChar("tries", attempt);

  uint8_t salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN], key[KEY_LEN];
  uint8_t ct[MAX_PLAIN], plain[MAX_PLAIN];
  uint8_t elen    = p.getUChar("elen", 0);
  uint8_t plen    = p.getUChar("plen", 0);   // 0 for wallets made before passphrases
  size_t  total   = (size_t)elen + plen;
  size_t  gotCt   = p.getBytes("ct", ct, sizeof(ct));
  size_t  gotSalt = p.getBytes("salt", salt, SALT_LEN);
  size_t  gotIv   = p.getBytes("iv", iv, IV_LEN);
  size_t  gotTag  = p.getBytes("tag", tag, TAG_LEN);

  LoadResult result = LOAD_ERROR;
  if (elen > 0 && elen <= MAX_ENT && plen <= MAX_PASSPHRASE && total <= MAX_PLAIN &&
      gotCt == total && gotSalt == SALT_LEN && gotIv == IV_LEN && gotTag == TAG_LEN &&
      deriveKey(pin, salt, key)) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, KEY_LEN * 8) == 0) {
      int rc = mbedtls_gcm_auth_decrypt(&gcm, total, iv, IV_LEN,
                                        (const unsigned char *)AAD, strlen(AAD),
                                        tag, TAG_LEN, ct, plain);
      if (rc == 0) {
        memcpy(entropy, plain, elen);
        *outLen = elen;
        if (passphrase && passMax > plen) {
          memcpy(passphrase, plain + elen, plen);
          passphrase[plen] = '\0';
        }
        p.putUChar("tries", 0);   // reset on success
        result = LOAD_OK;
      } else {
        if (attempt >= PIN_MAX_TRIES) {
          result = LOAD_WIPED;
        } else {
          result = LOAD_WRONG_PIN;
          if (triesLeft) *triesLeft = PIN_MAX_TRIES - attempt;
        }
      }
    }
    mbedtls_gcm_free(&gcm);
  }

  mbedtls_platform_zeroize(key, sizeof(key));
  mbedtls_platform_zeroize(ct, sizeof(ct));
  mbedtls_platform_zeroize(plain, sizeof(plain));
  p.end();

  if (result == LOAD_WIPED) wipe();
  return result;
}

// Deliberately its own NVS namespace ("cwid"), separate from NVS_NAMESPACE
// ("cw") — wipe() only ever clears the latter, so this survives a full
// wallet wipe/restore, matching a physical serial number's lifetime rather
// than the wallet's own.
uint16_t deviceId() {
  Preferences p;
  if (!p.begin("cwid", false)) return 0;   // read-write: may need to generate
  if (p.isKey("id")) {
    uint16_t id = p.getUShort("id", 0);
    p.end();
    return id;
  }
  uint16_t id = (uint16_t)(esp_random() & 0xFFFF);
  p.putUShort("id", id);
  p.end();
  return id;
}

}  // namespace store
