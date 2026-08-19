#pragma once
//
// Encrypted seed storage in NVS.
//
// The BIP39 entropy is encrypted with AES-256-GCM. The key is derived from the
// user PIN with PBKDF2-HMAC-SHA256 over a random per-wallet salt, so the PIN is
// never stored and a wrong PIN simply fails the GCM authentication. A persisted
// wrong-attempt counter triggers a self-wipe after PIN_MAX_TRIES.
//
// NOTE: at this phase the ciphertext lives in ordinary (unencrypted) flash.
// Flash encryption + Secure Boot v2 are enabled in Phase 7; until then, at-rest
// protection rests on the PIN-derived key and the wipe counter only.

#include <Arduino.h>

namespace store {

enum LoadResult {
  LOAD_OK,          // decrypted successfully
  LOAD_WRONG_PIN,   // authentication failed; attempts remain
  LOAD_WIPED,       // too many wrong attempts — wallet erased
  LOAD_EMPTY,       // no seed stored
  LOAD_ERROR        // storage/crypto error
};

// Is there an encrypted seed present?
bool hasSeed();

// Max BIP39 passphrase length we store.
static const size_t MAX_PASSPHRASE = 64;

// Encrypt `entropy` (entLen bytes, <=32) plus an optional BIP39 `passphrase`
// (may be "" for none) under `pin` and persist it. Resets the wrong-attempt
// counter. Returns true on success.
bool saveSeed(const uint8_t *entropy, size_t entLen, const char *passphrase, const char *pin);

// Attempt to decrypt with `pin`. On LOAD_OK, writes the entropy into `entropy`
// (buffer >=32) and sets *outLen, and writes the passphrase into `passphrase`
// (buffer >= MAX_PASSPHRASE+1, NUL-terminated). On a wrong PIN, *triesLeft is
// set to the remaining attempts. The attempt counter is incremented in flash
// BEFORE the check, so a power-cycle mid-attempt cannot bypass the limit.
LoadResult loadSeed(const char *pin, uint8_t *entropy, size_t *outLen,
                    char *passphrase, size_t passMax, uint8_t *triesLeft);

// Erase all wallet data.
void wipe();

// Remaining wrong-PIN attempts before wipe.
uint8_t triesRemaining();

// BLE transport enable (non-secret setting). Defaults to OFF. Cleared on wipe.
bool bleEnabled();
void setBleEnabled(bool on);

// Selected coin (non-secret setting): COIN_BTC (default) or COIN_ETH. Cleared on wipe.
uint8_t coin();
void    setCoin(uint8_t c);

// Battery-saver auto-lock timeout, in minutes (non-secret setting). 0 means
// "Off" (auto-lock disabled entirely). Replaces the old fixed AUTO_LOCK_MS
// constant with a user-configurable value (Settings > Battery Saver).
// Defaults to 3 (the value this replaces). Cleared on wipe.
uint8_t autoLockMinutes();
void    setAutoLockMinutes(uint8_t minutes);

// Selected UI language, as an index into the 11-locale list shown in
// Settings (same set as the app/landing site). Purely a stored preference
// for now - nothing on-device actually changes with it yet; a placeholder
// until a real translation pass happens. Defaults to 0 (English). Cleared
// on wipe.
uint8_t language();
void    setLanguage(uint8_t idx);

// Bitmask of coins activated by the app via ADDR_REQ (bit i = COIN_i is active).
// Stored as a byte array (not a single 32-bit int — this wallet has more than
// 32 coins) sized to COIN_MASK_BYTES bytes = COIN_MASK_BYTES*8 representable
// coins, comfortably above COIN_COUNT with room to grow. Defaults to all-
// inactive. Cleared on wipe().
static const size_t COIN_MASK_BYTES = 32;   // 256 coins' worth of bits

void     activateCoin(uint8_t c);
void     deactivateCoin(uint8_t c);   // clears only the coin's own active bit
                                       // — account data/naccts/names are left
                                       // untouched, so re-activating restores
                                       // previously-created accounts as-is.
bool     isCoinActive(uint8_t c);
bool     anyCoinActive();   // true if at least one coin is active anywhere
// Read the whole mask once into out[COIN_MASK_BYTES] to avoid repeated NVS
// reads in a per-coin loop (SYNC_REQ, home-menu coin-picker fallback).
void     coinMaskBytes(uint8_t *out);

// Bitmask of activated account indices for coin c (bit N = account index N active).
// coinAccountCount returns popcount of the mask. Cleared on wipe().
uint8_t coinAccountCount(uint8_t c);          // number of active accounts
uint8_t coinAccountMask(uint8_t c);           // raw bitmask (bit N = account N active)
void    setCoinAccountMask(uint8_t c, uint8_t mask); // overwrite entire mask
void    activateAccountBit(uint8_t c, uint8_t idx);   // set bit idx
void    deactivateAccountBit(uint8_t c, uint8_t idx); // clear bit idx

// Per-coin "blind signing allowed" toggle (non-secret setting). Off by
// default - a coin whose review screen can only ever show a blind-sign
// hash (no itemized decode) refuses to sign at all until this is turned
// on for it, mirroring how Ledger's own per-app "Blind signing" setting
// works. Stored the same way as the coin-activation mask (a
// COIN_MASK_BYTES-byte array under its own key, not a single int).
// Cleared on wipe() (same NVS namespace as every other setting above).
bool isBlindSignAllowed(uint8_t c);
void setBlindSignAllowed(uint8_t c, bool allowed);

// Custom account label for (coin c, account idx). Returns "" if none set.
// Labels are stored in NVS as "acn{c}" blobs. Cleared on wipe().
const char* accountName(uint8_t c, uint8_t idx);
void        setAccountName(uint8_t c, uint8_t idx, const char* name);
void        clearAccountName(uint8_t c, uint8_t idx);

// One-time migration: clears naccts if stored in old count format (pre-v2).
// Call once from setup() before any account operations.
void migrateIfNeeded();

// Stable per-unit device identity (NOT the radio MAC — see the note where
// this is called) — a 16-bit value generated once via the chip's real HWRNG
// (esp_random(), already used elsewhere in this firmware for entropy) on its
// very first call ever, then persisted and reused for the life of the unit.
// Lives in its own NVS namespace (separate from NVS_NAMESPACE's wallet
// blobs), so a wallet wipe() does NOT reset it — this identifies the
// physical device for BLE/UI display purposes, a hardware-level property
// that shouldn't change just because the wallet on it was reset, the same
// way a product's printed serial number wouldn't.
uint16_t deviceId();

}  // namespace store
