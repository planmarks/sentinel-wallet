//
// Sentinel — Phase 6: optional BLE transport
//
// Cumulative features:
//  * BIP39 seed generation OR restore (enter an existing 12-word phrase via
//    letter-prefix autocomplete) — recovery after a wrong-PIN self-wipe.
//  * Optional BIP39 passphrase (25th word), stored encrypted with the seed.
//  * AES-256-GCM encrypted storage keyed by PBKDF2(PIN).
//  * Boot unlock; wrong-PIN self-wipe counter (survives power-cycle).
//  * Receive: BIP84 native-segwit addresses (m/84'/coin'/0'/0/i) as text + QR.
//  * Sign Tx: PSBT in over serial OR BLE, review outputs+fee on-device, hold
//    SELECT to confirm, device signs offline and returns the signed PSBT.
//  * Multi-coin: main-menu Coin cycles BTC / ETH / SOL / XLM / ADA, each with
//    receive + signing. ed25519 (SOL/XLM/ADA) via vendored TweetNaCl; Cardano
//    adds Icarus + BIP32-Ed25519 + Blake2b (vendored). ADA signing is blind-sign.
//  * Settings: coin, BLE on/off (default off), export xpub, wipe. Mainnet
//    only — this device line never supports testnet (removed 2026-08-09: a
//    stale isTestnet() NVS setting defaulted to testnet with no actual
//    on-device toggle ever wired up to change it, since setTestnet() was
//    never called from anywhere in this file).
//
// BLE is only a transport: a PSBT over BLE still needs on-device confirmation,
// and the radio only comes up after unlock. Secrets live only in RAM and are
// zeroized after use. The mnemonic is shown only on the OLED, never on Serial.
//
// Target: Seeed XIAO ESP32-C5  |  Arduino-ESP32 core 3.3.5+
// Requires libraries: U8g2, uBitcoin, NimBLE-Arduino (QRCode vendored as qrcodegen.*)
//
#include <nvs_flash.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "config.h"
#include "display.h"
#include "buttons.h"
#include "wallet.h"
#include "store.h"
#include "i18n.h"
#include "signer.h"
#include "ble.h"
#include "eth.h"
#include "bnb.h"
#include "xrp.h"
#include <Networks.h>
#include "sol.h"
#include "xlm.h"
#include "ada.h"
#include "cosmos.h"
#include "tron.h"
#include "ton.h"
#include "dot.h"
#include "sui.h"
#include "apt.h"
#include "near.h"
#include "algo.h"
#include "bch.h"
#include "fil.h"

// ESP-IDF sleep APIs for the low-power idle state (CPU light sleep + GPIO wake).
#include "esp_sleep.h"
#include "driver/gpio.h"
#include "esp_random.h"

// The default Arduino loop task stack (8 KB) is too small for the ed25519
// scalar multiplication (Solana/Stellar) on top of the UI/crypto call chain.
// Enlarge it so key derivation doesn't overflow the stack and reboot the device.
SET_LOOP_TASK_STACK_SIZE(24 * 1024);

// ---- Alt-UTXO network constants -------------------------------------------
// uBitcoin's Network struct: p2pkh, p2sh, bech32[5], wif,
//   xprv[4], yprv[4], zprv[4], Yprv[4], Zprv[4],
//   xpub[4], ypub[4], zpub[4], Ypub[4], Zpub[4], bip32 (coin type)

static const Network LtcMainnet = {
  0x30, 0x32, "ltc", 0xB0,
  {0x01,0x9D,0xA5,0x20}, {0x01,0xB8,0xC1,0x11}, {0x04,0xB2,0x43,0x0C},
  {0x02,0x95,0xB0,0x05}, {0x02,0xAA,0x7A,0x99},
  {0x01,0x9D,0xA4,0x62}, {0x01,0xB2,0x6E,0xF6}, {0x04,0xB2,0x47,0x46},
  {0x02,0x95,0xB4,0x3F}, {0x02,0xAA,0x7E,0xD3},
  2  // BIP44 coin type
};

static const Network DogeMainnet = {
  0x1E, 0x16, "", 0x9E,
  {0x02,0xFA,0xC3,0x98}, {0x02,0xFA,0xC3,0x98}, {0x02,0xFA,0xC3,0x98},
  {0x02,0xFA,0xC3,0x98}, {0x02,0xFA,0xC3,0x98},
  {0x02,0xFA,0xCA,0xFD}, {0x02,0xFA,0xCA,0xFD}, {0x02,0xFA,0xCA,0xFD},
  {0x02,0xFA,0xCA,0xFD}, {0x02,0xFA,0xCA,0xFD},
  3  // BIP44 coin type
};

// Params verified against Trezor's own coin registry (trezor-common defs/bitcoin/*.json).
static const Network DashMainnet = {
  0x4C, 0x10, "", 0xCC,
  {0x02,0xFE,0x52,0xF8}, {0x02,0xFE,0x52,0xF8}, {0x02,0xFE,0x52,0xF8},
  {0x02,0xFE,0x52,0xF8}, {0x02,0xFE,0x52,0xF8},
  {0x02,0xFE,0x52,0xCC}, {0x02,0xFE,0x52,0xCC}, {0x02,0xFE,0x52,0xCC},
  {0x02,0xFE,0x52,0xCC}, {0x02,0xFE,0x52,0xCC},
  5  // BIP44 coin type
};

static const Network DgbMainnet = {
  0x1E, 0x3F, "dgb", 0x9E,
  {0x04,0x88,0xAD,0xE4}, {0x04,0x9D,0x78,0x78}, {0x04,0xB2,0x43,0x0C},
  {0x04,0x9D,0x78,0x78}, {0x04,0xB2,0x43,0x0C},
  {0x04,0x88,0xB2,0x1E}, {0x04,0x9D,0x7C,0xB2}, {0x04,0xB2,0x47,0x46},
  {0x04,0x9D,0x7C,0xB2}, {0x04,0xB2,0x47,0x46},
  20  // BIP44 coin type
};

static const Network RvnMainnet = {
  0x3C, 0x7A, "", 0xBC,
  {0x04,0x88,0xAD,0xE4}, {0x04,0x88,0xAD,0xE4}, {0x04,0x88,0xAD,0xE4},
  {0x04,0x88,0xAD,0xE4}, {0x04,0x88,0xAD,0xE4},
  {0x04,0x88,0xB2,0x1E}, {0x04,0x88,0xB2,0x1E}, {0x04,0x88,0xB2,0x1E},
  {0x04,0x88,0xB2,0x1E}, {0x04,0x88,0xB2,0x1E},
  175  // BIP44 coin type
};

Display display;
Buttons  buttons;

// ---- Unlocked wallet state (RAM only) --------------------------------------
static uint8_t g_entropy[32];
static size_t  g_entropyLen = 0;
static char    g_passphrase[store::MAX_PASSPHRASE + 1] = {0};  // BIP39 passphrase (may be empty)
static bool    g_unlocked   = false;
static String  g_masterFp  = "";   // cached BIP32 fingerprint; cleared on lock

// Timestamp of the last user interaction (any button). Drives the inactivity
// auto-lock; updated wherever a button event is consumed.
static uint32_t g_lastActivityMs = 0;

static void lockWallet() {
  wallet::zeroize(g_entropy, sizeof(g_entropy));
  wallet::zeroize(g_passphrase, sizeof(g_passphrase));
  g_entropyLen = 0;
  g_unlocked   = false;
  g_masterFp   = "";
}

// ---- Menus ------------------------------------------------------------------
static const char *coinName(uint8_t c) {
  switch (c) {
    case COIN_ETH:  return "ETH";
    case COIN_XRP:  return "XRP";
    case COIN_DASH:   return "DASH";
    case COIN_DGB:    return "DGB";
    case COIN_RVN:    return "RVN";
    case COIN_TIA:    return "TIA";
    case COIN_ATOM: return "ATOM";
    case COIN_DYDX: return "DYDX";
    case COIN_AXL:  return "AXL";
    case COIN_BABY: return "BABY";
    case COIN_BCH:  return "BCH";
    case COIN_TRX:  return "TRX";
    case COIN_TON:  return "GRAM";
    case COIN_DOT:      return "DOT";
    case COIN_FIL:      return "FIL";
    case COIN_SUI:      return "SUI";
    case COIN_APT:      return "APT";
    case COIN_NEAR:     return "NEAR";
    case COIN_ALGO:     return "ALGO";
    case COIN_USDTTRX:  return "USDTTRX";
    case COIN_BTTTRX:   return "BTTTRX";
    case COIN_SOL:  return "SOL";
    case COIN_XLM:  return "XLM";
    case COIN_ADA:  return "ADA";
    case COIN_LTC:  return "LTC";
    case COIN_DOGE: return "DOGE";
    default:        return "BTC";
  }
}

static const char *coinDisplayName(uint8_t c) {
  switch (c) {
    case COIN_ETH:     return "Ethereum";
    case COIN_XRP:     return "Ripple";
    case COIN_DASH:   return "Dash";
    case COIN_DGB:    return "DigiByte";
    case COIN_RVN:    return "Ravencoin";
    case COIN_TIA:    return "Celestia";
    case COIN_ATOM:    return "Cosmos Hub";
    case COIN_DYDX:    return "dYdX";
    case COIN_AXL:     return "Axelar";
    case COIN_BABY:    return "Babylon";
    case COIN_BCH:     return "Bitcoin Cash";
    case COIN_TRX:     return "Tron";
    case COIN_TON:     return "Gram";
    case COIN_DOT:     return "Polkadot";
    case COIN_FIL:     return "Filecoin";
    case COIN_SUI:     return "Sui";
    case COIN_APT:     return "Aptos";
    case COIN_NEAR:    return "NEAR Protocol";
    case COIN_ALGO:    return "Algorand";
    case COIN_USDTTRX: return "USDT (TRC20)";
    case COIN_BTTTRX:  return "BTT (TRC20)";
    case COIN_SOL:     return "Solana";
    case COIN_XLM:     return "Stellar";
    case COIN_ADA:     return "Cardano";
    case COIN_LTC:     return "Litecoin";
    case COIN_DOGE:    return "Dogecoin";
    default:           return "Bitcoin";
  }
}

// EVM chains all share Ethereum's key/address and EIP-1559 signing (eth.cpp);
// only the chainId (carried in the tx line) differs. Every EVM chain and
// every ERC-20 token now signs through this one slot — see the note atop
// config.h for why none of them get their own COIN_* id anymore.
static bool isEvmCoin(uint8_t c) {
  return c == COIN_ETH;
}

// SPL tokens would share Solana's keypair/address and message-signing
// (sol.cpp) the same way ERC-20 tokens share isEvmCoin() — no ERC-20/BEP-20
// or SPL token gets its own COIN_* id; a token transfer signs through its
// native chain's signer, which decodes the transfer generically from the
// transaction bytes for display. See eth::txIsErc20()/txSymbol().
static bool isSolFamily(uint8_t c) {
  return c == COIN_SOL;
}

// Display label for a coin — TRC-20 variants show the parent symbol so the menu
// only says "USDT" / "USDC"; the network is shown separately in the picker.
static const char* coinLabel(uint8_t c) {
  if (c == COIN_USDTTRX) return "USDT";
  if (c == COIN_BTTTRX) return "BTT";
  return coinName(c);
}

// Map a symbol string (sent by the app) to its COIN_* constant. Every EVM
// leaf chain (BNB, AVAX, ...) and ERC-20 token (USDT, USDC, ...) the app may
// still ask for by name maps to COIN_ETH — same key/address, and eth.cpp
// derives the correct wire response label from the payload itself (see
// eth::txSignLabel()), not from which coin this resolves to.
static uint8_t coinFromSymbol(const String& sym) {
  if (sym == "BTC")     return COIN_BTC;
  if (sym == "ETH" || sym == "BNB" || sym == "USDT" || sym == "USDC" ||
      sym == "AVAX" || sym == "BASE" || sym == "POL" || sym == "CRO" ||
      sym == "OP" || sym == "ARB" || sym == "FTM" || sym == "ETC" ||
      sym == "LINEA" || sym == "CELO" || sym == "MNT" || sym == "HYPE" ||
      sym == "OKB" || sym == "KCS" || sym == "XDC" || sym == "FLR" ||
      sym == "FILEVM" || sym == "BTT" || sym == "MON" || sym == "XTZ" ||
      sym == "IOTA" || sym == "S" || sym == "XPL" || sym == "KAIA" ||
      sym == "M")
    return COIN_ETH;
  if (sym == "SOL")     return COIN_SOL;
  if (sym == "XRP")     return COIN_XRP;
  if (sym == "ADA")     return COIN_ADA;
  if (sym == "XLM")     return COIN_XLM;
  if (sym == "ATOM")    return COIN_ATOM;
  if (sym == "DYDX")    return COIN_DYDX;
  if (sym == "AXL")     return COIN_AXL;
  if (sym == "BABY")    return COIN_BABY;
  if (sym == "BCH")     return COIN_BCH;
  if (sym == "TRX")     return COIN_TRX;
  if (sym == "GRAM")    return COIN_TON;
  if (sym == "DOT")     return COIN_DOT;
  if (sym == "FIL")     return COIN_FIL;
  if (sym == "SUI")     return COIN_SUI;
  if (sym == "APT")     return COIN_APT;
  if (sym == "NEAR")    return COIN_NEAR;
  if (sym == "ALGO")    return COIN_ALGO;
  if (sym == "USDTTRX") return COIN_USDTTRX;
  if (sym == "BTTTRX") return COIN_BTTTRX;
  if (sym == "LTC")     return COIN_LTC;
  if (sym == "DOGE")    return COIN_DOGE;
  if (sym == "DASH")   return COIN_DASH;
  if (sym == "DGB")    return COIN_DGB;
  if (sym == "RVN")    return COIN_RVN;
  if (sym == "TIA")    return COIN_TIA;
  return COIN_BTC;
}

// Advance / retreat through active coins only.
// Returns current coin unchanged if no other active coin exists.
static uint8_t nextCoin(uint8_t c) {
  uint8_t orig = c;
  do {
    c = (c + 1) % COIN_COUNT;
    if (c == orig) return c;
  } while (!store::isCoinActive(c));
  return c;
}
static uint8_t prevCoin(uint8_t c) {
  uint8_t orig = c;
  do {
    c = (uint8_t)((c + COIN_COUNT - 1) % COIN_COUNT);
    if (c == orig) return c;
  } while (!store::isCoinActive(c));
  return c;
}

// Settings menu: Bluetooth toggle, Battery Saver, Language, Device
// Information, Uninstall All Coins, Change PIN, Reset Device. Bluetooth is
// drawn as an animated switch graphic (Display::settingsMenu), not
// "ON"/"OFF" text; the rest are plain action rows that open their own
// sub-screen or modal.
static const uint8_t kSettingsCount = 7;
static Display::SettingsRow settingsRows[kSettingsCount];
static void buildSettings() {
  uint8_t lg = store::language();
  settingsRows[0] = { "Bluetooth", true, store::bleEnabled() };   // brand name - never translated
  settingsRows[1] = { i18n::tr(lg, i18n::S_BATTERY_SAVER), false, false };
  settingsRows[2] = { i18n::tr(lg, i18n::S_LANGUAGE), false, false };
  settingsRows[3] = { i18n::tr(lg, i18n::S_DEVICE_INFORMATION), false, false };
  settingsRows[4] = { i18n::tr(lg, i18n::S_UNINSTALL_ALL_COINS), false, false };
  settingsRows[5] = { i18n::tr(lg, i18n::S_CHANGE_PIN), false, false };
  settingsRows[6] = { i18n::tr(lg, i18n::S_RESET_DEVICE), false, false };
}

// ---- Battery Saver picker (Off/1/3/5/10 min) --------------------------------
static const uint8_t kBatterySaverCount = 5;
static const char *  kBatterySaverLabels[kBatterySaverCount];   // filled by buildBatterySaverLabels()
static const uint8_t kBatterySaverMinutes[kBatterySaverCount] = { 0, 1, 3, 5, 10 };
static uint8_t     g_batterySaverSel = 0;

static void buildBatterySaverLabels() {
  uint8_t lg = store::language();
  kBatterySaverLabels[0] = i18n::tr(lg, i18n::S_OFF);
  kBatterySaverLabels[1] = i18n::tr(lg, i18n::S_1_MINUTE);
  kBatterySaverLabels[2] = i18n::tr(lg, i18n::S_3_MINUTES);
  kBatterySaverLabels[3] = i18n::tr(lg, i18n::S_5_MINUTES);
  kBatterySaverLabels[4] = i18n::tr(lg, i18n::S_10_MINUTES);
}

// ---- Language picker --------------------------------------------------------
// Only the 5 languages i18n.cpp actually has translations for - the other 6
// the app/landing site offer (Vietnamese, Hindi, Arabic, Korean, Japanese,
// Chinese) need either a script-shaping engine (Arabic/Hindi) or a full
// bigger-glyph layout rework (Vietnamese/Korean/Japanese/Chinese) the OLED
// firmware doesn't have yet - see i18n.h. English names, not native scripts.
static const uint8_t kLanguageCount = i18n::LANG_SUPPORTED_COUNT;
static const char *const kLanguageLabels[kLanguageCount] = {
  "English", "Spanish", "Portuguese", "Estonian", "Russian"
};
static uint8_t     g_languageSel = 0;

// ---- Device Information -----------------------------------------------------
// Static (not stack-local) — Display::message() stores the body pointer and
// re-reads it on every redraw while this screen is showing, so it must
// outlive the function that formats it.
static char deviceInfoBody[80];

// Coin-specific Settings (reached from the coin-menu's "Settings" item) -
// separate from the global Settings screen above (BLE/Reset, reached only
// from the home-menu's own Settings icon). Just the blind-signing toggle
// for whichever coin is currently selected, for now - also an animated
// switch graphic, same as BLE above.
static const uint8_t kCoinSettingsCount = 1;
static Display::SettingsRow coinSettingsRows[kCoinSettingsCount];
static uint8_t       g_coinSettingsSel = 0;
static void buildCoinSettings() {
  coinSettingsRows[0] = { "Blind sign", true, store::isBlindSignAllowed(store::coin()) };
}

// Name used for the coin-settings title bar ("<name> Settings") - normally
// just coinDisplayName(), except where the full name is too long to fit
// alongside " Settings" on the 128px-wide title bar at 6px/char.
static const char *coinSettingsTitleName(uint8_t c) {
  if (c == COIN_NEAR) return "NEAR Prot.";
  return coinDisplayName(c);
}

// Whether coin `c` could ever need the blind-signing toggle at all - unlike
// isBlindSignTx() (below, tx-content-dependent), this only depends on the
// coin family, since Settings needs an answer before any transaction
// exists. False for the PSBT family (BTC/LTC/DOGE/DASH/DGB/RVN) and the
// whole EVM family - both always decode generically and are never
// blind-sign, so the toggle would have no effect there.
static bool coinHasBlindSignSetting(uint8_t c) {
  if (isEvmCoin(c)) return false;
  switch (c) {
    case COIN_BTC: case COIN_LTC: case COIN_DOGE: case COIN_DASH:
    case COIN_DGB: case COIN_RVN:
      return false;
    default:
      return true;
  }
}

// Plays a short slide animation for the toggle at row `sel` (0..count-1
// must be a toggle row), then returns with the animation left on its
// final frame - the caller is responsible for actually persisting the
// new value and letting the next normal render() redraw the settled
// state. Reuses the exact same settingsMenu() draw call the screen's own
// render() uses (just with an in-between knob position each frame), so
// there's no separate/forked rendering path to keep in sync.
static void animateToggleRow(const char *title, Display::SettingsRow *rows,
                              uint8_t count, uint8_t sel, bool turningOn) {
  const uint8_t kSteps = 6;
  for (uint8_t i = 1; i <= kSteps; i++) {
    float pos = turningOn ? (float)i / kSteps : 1.0f - (float)i / kSteps;
    display.settingsMenu(title, rows, count, sel, pos);
    delay(18);
  }
}

enum Screen {
  SCREEN_MENU, SCREEN_SETTINGS, SCREEN_STUB,
  SCREEN_RECEIVE_QR, SCREEN_SIGN_REVIEW, SCREEN_SIGN_DONE,
  SCREEN_ACCOUNT_LIST, SCREEN_COIN_READY, SCREEN_SIGN_SELECT, SCREEN_COIN_MENU,
  SCREEN_COIN_SETTINGS, SCREEN_COIN_ABOUT, SCREEN_BATTERY_SAVER,
  SCREEN_LANGUAGE, SCREEN_DEVICE_INFO
};
static Screen  screen          = SCREEN_MENU;
static uint8_t selected         = 0;   // main menu cursor
static bool    g_usbAppConnected = false;  // true only after Sentinel app sends HELLO
// Placeholder battery percentage — this device has no battery yet, so
// there's nothing real to read. Set once in setup() via the HWRNG so the
// home-menu Battery slot has a plausible-looking value to show instead of
// a fixed number, without pretending to be a live reading.
static uint8_t g_batteryPct = 0;
static uint8_t settingsSel  = 0;   // settings menu cursor
static const char *stubTitle = "";
static const char *stubBody  = "";
static bool        stubCentered = false;  // true: no title bar, body centered (e.g. About)

// ---- Account picker state ---------------------------------------------------
static uint8_t     g_acctListSel  = 0;
static uint8_t     g_acctCount    = 0;
static char        g_acctLabels[10][20];   // "USDT 0 ERC-20\0" = 14 chars; 20 is safe
static const char* g_acctPtrs[10];
static uint8_t     g_acctBipIndex[10];    // BIP44 account index for each picker slot
static uint8_t     g_acctCoins[10];       // COIN_* for each picker slot (may differ from store::coin() for TRC-20)

// USDT/USDC (ERC-20) used to merge here with their TRC-20 variant into one
// shared-index list — that merge was only ever reachable by first selecting
// COIN_USDT/COIN_USDC, which the app never actually activated (its
// account-creation flow always resolves USDT/USDC to 'ETH', see the note
// atop config.h), so it was dead in practice. USDTTRX now shows its own
// plain account list like any other coin, same as everything below.
static void buildAccountItems() {
  uint8_t c     = store::coin();
  uint8_t mask  = store::coinAccountMask(c);
  uint8_t listIdx = 0;
  const char* name = coinDisplayName(c);
  for (uint8_t bit = 0; bit < 8 && listIdx < 10; bit++) {
    if (!(mask & (1u << bit))) continue;
    const char* custom = store::accountName(c, bit);
    if (custom[0] != '\0')
      snprintf(g_acctLabels[listIdx], sizeof(g_acctLabels[listIdx]), "%s", custom);
    else
      snprintf(g_acctLabels[listIdx], sizeof(g_acctLabels[listIdx]), "%s %u", name, (unsigned)bit);
    g_acctPtrs[listIdx]   = g_acctLabels[listIdx];
    g_acctBipIndex[listIdx] = bit;
    g_acctCoins[listIdx]    = c;
    listIdx++;
  }
  g_acctCount = listIdx;
}

// ---- Receive view state -----------------------------------------------------
static uint32_t g_recvIndex = 0;
static uint8_t  g_recvCoin  = 0;   // coin used for address derivation; set before updateReceive()
static String   g_recvAddr;
static String   g_recvPath;

// ---- Sign-select confirmation state -----------------------------------------
// Coin the app named via SIGN_SELECT|<SYMBOL>, awaiting the user's on-device
// approval (SCREEN_SIGN_SELECT) before store::coin() actually switches to it.
static uint8_t g_pendingSignCoin = 0;
// Transport the SIGN_SELECT request itself arrived on - same reasoning as
// g_signSource: the response (SIGN_SELECT_OK>/SIGN_SELECT_CANCEL>) only
// fires later, once the user presses a button on SCREEN_SIGN_SELECT, by
// which point the original request's transport is no longer directly
// inspectable, so it's captured up front instead.
static SignSource g_signSelectSource = SRC_SERIAL;

// Reached from SCREEN_COIN_READY by pressing DOWN; UP always returns there.
// "Settings" is only listed at all for a coin that actually has a setting
// to show (see coinHasBlindSignSetting()) - rather than a screen with a
// dead/useless message, the item itself just isn't there.
static const char *const kCoinMenuItemsFull[]         = { "Receive", "Settings", "About" };
static const char *const kCoinMenuItemsReceiveAbout[] = { "Receive", "About" };
static uint8_t       g_coinMenuSel = 0;
static const char *const *coinMenuItems() {
  return coinHasBlindSignSetting(store::coin()) ? kCoinMenuItemsFull
                                                 : kCoinMenuItemsReceiveAbout;
}
static uint8_t coinMenuCount() {
  return coinHasBlindSignSetting(store::coin()) ? 3 : 2;
}
static void updateReceive() {
  uint8_t c = g_recvCoin;
  if (isEvmCoin(c))                 // ETH/BNB/USDT/USDC/AVAX/BASE/POL/CRO share the ETH address
    g_recvAddr = eth::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_XRP)
    g_recvAddr = xrp::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_ATOM)
    g_recvAddr = cosmos::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex, "cosmos");
  else if (c == COIN_DYDX)
    g_recvAddr = cosmos::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex, "dydx");
  else if (c == COIN_AXL)
    g_recvAddr = cosmos::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex, "axelar");
  else if (c == COIN_BABY)
    g_recvAddr = cosmos::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex, "bbn");
  else if (c == COIN_TIA)
    g_recvAddr = cosmos::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex, "celestia");
  else if (c == COIN_TRX)
    g_recvAddr = tron::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_TON)
    g_recvAddr = ton::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_DOT)
    g_recvAddr = dot::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_FIL)
    g_recvAddr = fil::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_SUI)
    g_recvAddr = sui::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_APT)
    g_recvAddr = apt::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_NEAR)
    g_recvAddr = near::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_ALGO)
    g_recvAddr = algo::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_USDTTRX || c == COIN_BTTTRX)
    g_recvAddr = tron::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (isSolFamily(c))
    g_recvAddr = sol::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_XLM)
    g_recvAddr = xlm::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_ADA)
    g_recvAddr = ada::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_LTC)
    g_recvAddr = wallet::deriveUTXOAddress(g_entropy, g_entropyLen, g_passphrase, &LtcMainnet, 2, true, g_recvIndex);
  else if (c == COIN_DOGE)
    g_recvAddr = wallet::deriveUTXOAddress(g_entropy, g_entropyLen, g_passphrase, &DogeMainnet, 3, false, g_recvIndex);
  else if (c == COIN_DASH)
    g_recvAddr = wallet::deriveUTXOAddress(g_entropy, g_entropyLen, g_passphrase, &DashMainnet, 5, false, g_recvIndex);
  else if (c == COIN_DGB)
    g_recvAddr = wallet::deriveUTXOAddress(g_entropy, g_entropyLen, g_passphrase, &DgbMainnet, 20, true, g_recvIndex);
  else if (c == COIN_BCH)
    g_recvAddr = bch::address(g_entropy, g_entropyLen, g_passphrase, g_recvIndex);
  else if (c == COIN_RVN)
    g_recvAddr = wallet::deriveUTXOAddress(g_entropy, g_entropyLen, g_passphrase, &RvnMainnet, 175, false, g_recvIndex);
  else
    g_recvAddr = wallet::receiveAddress(g_recvIndex, &g_recvPath);

  // Echo to Serial and BLE with coin tag so the app routes correctly.
  const char* coinTag = coinName(g_recvCoin);
  String addrLine = String("addr #") + g_recvIndex + " " + coinTag + ": " + g_recvAddr;
  Serial.println(addrLine);
  if (ble::isConnected()) ble::sendLine(addrLine);
}

// Notify the app that the wallet is unlocked and ready to serve requests.
// Includes the BIP32 master fingerprint (so the app can detect wallet
// changes) plus firmware version/chip id/NVS storage stats, all bundled
// into this one line rather than requiring separate STORAGE_REQ/
// DEVICE_INFO_REQ round-trips after connect. That used to be a real
// problem: those two commands would get queued behind WalletState's own
// (often long, many-round-trip) reconnect resync — which fires off this
// exact same SENTINEL_READY event on the app side — so they'd frequently
// time out waiting their turn. Piggybacking on the first thing sent after
// unlock means the app has this data immediately, before any resync
// traffic exists to queue behind. Fields are always present now (never a
// conditional/missing segment like the old fp-only version), so parsing by
// fixed split-index is reliable app-side.
static void notifyReady() {
  // Derive fingerprint once per unlock; cache it so BLE reconnects are instant.
  if (g_masterFp.length() == 0) {
    uint8_t savedCoin = store::coin();
    store::setCoin(COIN_BTC);
    if (wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) {
      g_masterFp = wallet::masterFingerprintHex();
      wallet::endReceive();
    }
    store::setCoin(savedCoin);
  }
  uint32_t usedBytes = 0, totalBytes = 0;
  nvs_stats_t stats;
  if (nvs_get_stats(NULL, &stats) == ESP_OK) {
    usedBytes  = (uint32_t)stats.used_entries  * 32;
    totalBytes = (uint32_t)stats.total_entries * 32;
  }
  // Same store::deviceId() the BLE scan-response advertises (ble.cpp) — one
  // stored random value, read by both, so there's exactly one id and no way
  // for these two paths to ever disagree with each other again. Replaces
  // the old ESP.getEfuseMac()-based id, which — despite both this line and
  // ble.cpp's computeIdentity() being *intended* to derive the same value
  // from the same MAC — was observed live to actually disagree between the
  // two on at least one real unit, most likely because that unit's flashed
  // firmware predated whichever revision made the two derivations agree.
  // A single stored value removes the possibility of that class of bug
  // entirely, rather than just fixing today's instance of it.
  char idHex[5];
  snprintf(idHex, sizeof(idHex), "%04X", (unsigned)store::deviceId());
  String line = String("SENTINEL_READY|") + g_masterFp + "|" + FW_VERSION +
                "|" + idHex + "|" + usedBytes + "|" + totalBytes;
  Serial.println(line);
  if (ble::isConnected()) ble::sendLine(line);
}

// ---- Sign view state --------------------------------------------------------
static uint8_t g_signPage = 0;   // 0..storedOutputs()-1 = outputs; last = summary
static SignSource g_signSource = SRC_SERIAL;   // where to return the signed PSBT (enum in config.h)


// Format satoshis as a BTC decimal string.
static String satToBtc(uint64_t sat) {
  char b[24];
  snprintf(b, sizeof(b), "%llu.%08llu",
           (unsigned long long)(sat / 100000000ULL),
           (unsigned long long)(sat % 100000000ULL));
  return String(b);
}

// "abcdef...uvwxyz" - first 6 + last 6 chars, for fitting a full address
// onto one summary-page line. Short strings are returned unchanged.
static String shortenAddr(const String &addr) {
  if (addr.length() <= 16) return addr;
  return addr.substring(0, 6) + "..." + addr.substring(addr.length() - 6);
}

// ---- Seed backup view -------------------------------------------------------
static String  g_seedWords[24];
static uint8_t g_seedCount = 0;

static void clearSeedState() {
  for (uint8_t i = 0; i < 24; i++) g_seedWords[i] = "";
  g_seedCount = 0;
}

static void splitMnemonic(const String &m) {
  clearSeedState();
  int start = 0;
  while (start < (int)m.length() && g_seedCount < 24) {
    int sp = m.indexOf(' ', start);
    if (sp < 0) { g_seedWords[g_seedCount++] = m.substring(start); break; }
    g_seedWords[g_seedCount++] = m.substring(start, sp);
    start = sp + 1;
  }
}

// ---- Blocking button helper -------------------------------------------------
static ButtonAction waitButton() {
  ButtonAction a;
  while (!buttons.poll(a)) delay(2);
  g_lastActivityMs = millis();   // interaction in a modal counts as activity
  return a;
}

static void waitForWakeButton();   // fwd decl (defined near auto-lock)

// Battery-saver auto-lock timeout in ms, from the user's configured minutes
// (Settings > Battery Saver, store::autoLockMinutes() — replaces the old
// fixed AUTO_LOCK_MS constant). 0 minutes = "Off": returns UINT32_MAX so
// both ">=" comparisons below never trigger, rather than special-casing
// "Off" at each call site.
static uint32_t autoLockMs() {
  uint8_t m = store::autoLockMinutes();
  if (m == 0) return UINT32_MAX;
  return (uint32_t)m * 60UL * 1000UL;
}

// ---- Modal: PIN entry (horizontal ruler 0-9) --------------------------------
// Left/Right (and Up/Down as aliases) slide the cursor along a 0-9 number line.
// Select commits the highlighted digit; a bare Select (cursor unmoved since last
// commit) with >= PIN_MIN_DIGITS committed confirms the PIN.
// Returns digit count, or -1 if cancelled. `out` must hold PIN_MAX_DIGITS+1.
static int pinEntryModal(const char *title, char *out, size_t maxDigits, bool dimOnIdle) {
  size_t   n = strlen(out);           // resume from any prefilled digits (e.g.
                                       // re-entering this step after backing
                                       // out of a later one) - a fresh call
                                       // must pass out[0]='\0' to start empty.
  if (n > maxDigits) n = maxDigits;
  uint8_t  pos = esp_random() % 10;   // 0-9 = digit, 10 = OK circle - starts on a
                                       // random digit, not always "0", so an
                                       // onlooker can't infer a digit from a
                                       // fixed number of cursor moves off a
                                       // known starting point.
  uint32_t idleStart = millis();

  for (;;) {
    char stars[PIN_MAX_DIGITS + 1];
    for (size_t i = 0; i < n; i++) stars[i] = '*';
    stars[n] = '\0';

    bool canConfirm = (n >= (size_t)PIN_MIN_DIGITS);
    display.pinEntry(title, stars, pos, canConfirm);

    ButtonAction a; bool got = false;
    for (;;) {
      if (buttons.poll(a)) { g_lastActivityMs = millis(); got = true; break; }
      if (dimOnIdle && (uint32_t)(millis() - idleStart) >= autoLockMs()) {
        display.sleep();
        waitForWakeButton();
        display.wake();
        idleStart = millis();
        break;
      }
      delay(2);
    }
    if (!got) continue;
    idleStart = millis();

    // BTN_LEFT physical = move cursor right (higher pos) — hardware inverted.
    // OK circle (pos 10) is reachable only when canConfirm; it wraps back to 0.
    uint8_t maxPos = 10;
    if (a.id == BTN_LEFT || a.id == BTN_DOWN) {
      pos = (pos < maxPos) ? pos + 1 : 0;
    } else if (a.id == BTN_RIGHT || a.id == BTN_UP) {
      pos = (pos > 0) ? pos - 1 : maxPos;
    } else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
      if (pos <= 9) {
        if (n < maxDigits) {
          out[n++] = (char)('0' + pos);
        }
        // Jump to a new random digit (never the same one just entered) so
        // the cursor never lands back where the user is expecting it.
        uint8_t newPos;
        do { newPos = esp_random() % 10; } while (newPos == pos);
        pos = newPos;
      } else if (canConfirm) {   // pos == 10, OK circle
        out[n] = '\0'; return (int)n;
      }
    } else if (a.id == BTN_BACK) {
      if (a.event == EV_LONGPRESS) {
        // Force back to the previous wizard step regardless of how many
        // digits are typed - but keep them in `out` (null-terminated at
        // the current length) so re-entering this step later resumes
        // right where it left off, rather than discarding progress.
        out[n] = '\0';
        return -1;
      }
      if (n > 0) {
        n--;
        if (pos == 10) pos = 9;  // step back off OK when digit removed
      } else {
        out[0] = '\0';
        return -1;
      }
    }
  }
}

// ---- Modal: hold-to-confirm -------------------------------------------------
static bool confirmModal(const char *title, const char *body, bool centered = false) {
  display.message(title, body, centered);
  for (;;) {
    ButtonAction a = waitButton();
    if (a.id == BTN_SELECT && a.event == EV_LONGPRESS) return true;
    if (a.id == BTN_BACK) return false;
  }
}

// Modal: enter a free-text passphrase by character selection. Up/Down cycle the
// charset, Select appends, hold Select finishes (empty allowed), Back deletes a
// char (or cancels if empty). Returns the length, or -1 if cancelled. The typed
// text is shown (this is a trusted setup screen). `out` must hold maxLen+1.
static int enterPassphraseModal(char *out, size_t maxLen) {
  static const char CH[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_!@#$";
  const int NCH = sizeof(CH) - 1;
  size_t n = 0;
  out[0] = '\0';
  int ci = 0;

  for (;;) {
    size_t len = strlen(out);
    const char *shown = (len > 14) ? out + (len - 14) : out;   // show the tail
    char body[48];
    snprintf(body, sizeof(body), "%s[%c]\nhold SEL=done BK=del", shown, CH[ci]);
    display.message("Passphrase", body);

    ButtonAction a = waitButton();
    if (a.id == BTN_UP) {
      ci = (ci + NCH - 1) % NCH;
    } else if (a.id == BTN_DOWN) {
      ci = (ci + 1) % NCH;
    } else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
      if (n < maxLen) { out[n++] = CH[ci]; out[n] = '\0'; }
    } else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS) {
      return (int)n;   // done (may be empty)
    } else if (a.id == BTN_BACK) {
      if (n > 0) { out[--n] = '\0'; } else return -1;
    }
  }
}

// ---- Flow: restore an existing wallet (first-boot alternative to
// generating a new seed) -------------------------------------------------

// Modal: choose New Device / Restore. Up/Down move the cursor, SEL confirms.
static const char *const kSetupChoices[2] = { "New Device", "Restore" };
// Returns 0/1 for the picked choice, or -1 if the user backed out (go to
// the previous wizard step - Welcome).
static int chooseSetupPath(uint8_t initialSel = 0) {
  uint8_t sel = initialSel;
  for (;;) {
    display.menu("Setup", kSetupChoices, 2, sel);
    ButtonAction a = waitButton();
    if      (a.id == BTN_UP)   sel = (sel == 0) ? 1 : 0;
    else if (a.id == BTN_DOWN) sel = (sel + 1) % 2;
    else if (a.id == BTN_SELECT && a.event == EV_PRESS) return sel;
    else if (a.id == BTN_BACK) return -1;   // no content here - always exits
  }
}

// Modal: choose a 12-, 18-, or 24-word restore (the 3 lengths the BIP39
// checksum implementation this device uses actually supports - see
// mnemonic_check() in trezor-crypto's bip39.c, which explicitly special-
// cases exactly these three word counts). A plain list menu, same shape
// and selection behaviour as every other picker in the app (e.g. Settings)
// - Up/Down move the cursor, a short SEL press confirms, BK cancels - no
// separate on-screen instruction text needed. Returns the word count, or
// 0 if cancelled.
static const char *const kWordCountChoices[3] = { "24 words", "18 words", "12 words" };
static const int         kWordCounts[3]        = { 24, 18, 12 };
static int chooseWordCountModal(int initial = 24) {
  uint8_t sel = 0;   // "24 words" (index 0) is the more common default
  for (uint8_t i = 0; i < 3; i++) if (kWordCounts[i] == initial) { sel = i; break; }
  // A caller resuming this step after a later back-out passes the
  // previously-chosen count via `initial` instead of always defaulting.
  for (;;) {
    display.menu("Restore", kWordCountChoices, 3, sel);
    ButtonAction a = waitButton();
    if      (a.id == BTN_UP)   sel = (sel == 0) ? 2 : sel - 1;
    else if (a.id == BTN_DOWN) sel = (sel + 1) % 3;
    else if (a.id == BTN_SELECT && a.event == EV_PRESS) return kWordCounts[sel];
    else if (a.id == BTN_BACK) return 0;
  }
}

// Modal: enter one BIP39 word by letter-prefix autocomplete. Up/Down cycle
// the current letter, Select commits it (narrowing the match), hold Select
// picks the shown word, Back deletes a letter (or - once the prefix is
// empty, or on a long-press from anywhere - cancels back to the previous
// word/step). Returns the wordlist index, or -1 to cancel. `initialWord`,
// when non-null, resumes on a previously-committed word for this slot
// (e.g. re-entering word N after backing out of word N+1) - the screen
// opens already fully typed, ready to reconfirm or edit.
static int enterWordModal(uint8_t pos, uint8_t total, const char *initialWord = nullptr) {
  char prefix[9];
  int letter = 0;  // 0..25 -> 'a'..'z'
  if (initialWord && initialWord[0]) {
    size_t wl = strlen(initialWord);
    if (wl > sizeof(prefix) - 1) wl = sizeof(prefix) - 1;
    memcpy(prefix, initialWord, wl - 1);
    prefix[wl - 1] = '\0';
    letter = initialWord[wl - 1] - 'a';
    if (letter < 0 || letter > 25) letter = 0;
  } else {
    prefix[0] = '\0';
  }

  for (;;) {
    size_t pl = strlen(prefix);
    char cand[10];
    memcpy(cand, prefix, pl);
    cand[pl] = (char)('a' + letter);
    cand[pl + 1] = '\0';

    int count = 0;
    int first = wallet::wordlistMatch(cand, &count);
    const char *top = (count > 0) ? wallet::wordlistAt(first) : "";

    char title[20];
    snprintf(title, sizeof(title), "Word %u/%u", pos, total);
    char typedLine[12];
    snprintf(typedLine, sizeof(typedLine), "%s_", cand);
    char matchLine[24];
    if (count > 0) snprintf(matchLine, sizeof(matchLine), "%s (%d)", top, count);
    else            snprintf(matchLine, sizeof(matchLine), "No match");
    const char *hint;
    if      (count == 1) hint = "Hold OK to continue";       // unique match - ready to accept
    else if (count > 1)  hint = "Press OK to pick letter";
    else                  hint = "Press back to delete";        // no match - nothing to add
    display.wordEntryPage(title, typedLine, matchLine, hint);

    ButtonAction a = waitButton();
    if (a.id == BTN_UP) {
      letter = (letter + 25) % 26;
    } else if (a.id == BTN_DOWN) {
      letter = (letter + 1) % 26;
    } else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
      if (count > 0 && pl < sizeof(prefix) - 2) {
        prefix[pl] = (char)('a' + letter);
        prefix[pl + 1] = '\0';
        letter = 0;
      }
    } else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS) {
      if (count > 0) return first;
    } else if (a.id == BTN_BACK) {
      if (a.event == EV_LONGPRESS) return -1;   // force back, skip letter-by-letter delete
      if (pl > 0) { prefix[pl - 1] = '\0'; letter = 0; }
      else return -1;
    }
  }
}

// Builds the mnemonic from g_seedWords/g_seedCount, converts to entropy,
// saves under `pin`, and on success updates the live in-RAM wallet state
// (g_entropy/g_entropyLen/g_passphrase/g_unlocked) and notifies the app.
// Does NOT zeroize `pin` or call clearSeedState() - callers own that, since
// some retry on failure before doing either.
static bool doSaveSeedAndUnlock(const char *pin) {
  String m;
  for (uint8_t i = 0; i < g_seedCount; i++) { if (i) m += ' '; m += g_seedWords[i]; }
  uint8_t ent[32];
  size_t  el = wallet::seedPhraseToEntropy(m, ent, sizeof(ent));
  m = "";

  bool ok = (el > 0) && store::saveSeed(ent, el, "", pin);
  if (ok) {
    memcpy(g_entropy, ent, el);
    g_entropyLen = el;
    g_passphrase[0] = '\0';
    g_unlocked = true;
    notifyReady();
  }
  wallet::zeroize(ent, sizeof(ent));
  return ok;
}

// ---- Flow: unlock existing wallet at boot -----------------------------------
// Returns true if unlocked; false if the wallet was wiped during the attempts.
static bool unlockFlow() {
  for (;;) {
    uint8_t lg = store::language();
    char pin[PIN_MAX_DIGITS + 1];
    pin[0] = '\0';
    int n = pinEntryModal(i18n::tr(lg, i18n::S_ENTER_PIN), pin, PIN_MAX_DIGITS, true);   // dim the PIN screen on idle
    if (n < 0) { continue; }   // cannot cancel out of the lock screen

    uint8_t left = 0;
    size_t  elen = 0;
    store::LoadResult r = store::loadSeed(pin, g_entropy, &elen,
                                          g_passphrase, sizeof(g_passphrase), &left);
    wallet::zeroize(pin, sizeof(pin));

    if (r == store::LOAD_OK) {
      g_entropyLen = elen;
      g_unlocked   = true;
      notifyReady();
      return true;
    }
    if (r == store::LOAD_WIPED) {
      display.message(i18n::tr(lg, i18n::S_WIPED), i18n::tr(lg, i18n::S_TOO_MANY_TRIES));
      delay(2500);
      lockWallet();
      return false;
    }
    if (r == store::LOAD_WRONG_PIN) {
      char m[48];
      snprintf(m, sizeof(m), "%s\n%u %s", i18n::tr(lg, i18n::S_WRONG_PIN_LINE), left, i18n::tr(lg, i18n::S_TRIES_LEFT));
      display.message(i18n::tr(lg, i18n::S_DENIED), m);
      delay(1500);
      continue;
    }
    display.message(i18n::tr(lg, i18n::S_ERROR), i18n::tr(lg, i18n::S_STORAGE_FAULT));
    delay(1500);
  }
}

// ---- Actions ----------------------------------------------------------------
static void showStub(const char *title, const char *body, bool centered = false) {
  stubTitle    = title;
  stubBody     = body;
  stubCentered = centered;
  screen       = SCREEN_STUB;
}

// Address-derivation failure, with which coin (and account index, when
// known) actually failed - a bare "derive error" gave no way to tell which
// of the many chains/accounts this app supports was the one that broke.
// `idx` may be -1 if no specific account index is known yet at the call
// site. Static body buffer: stubBody is just a pointer, so it must outlive
// this function's own stack frame for render() to read it correctly later.
static void showDeriveError(uint8_t coin, int idx) {
  static char body[40];
  if (idx >= 0) {
    // Same custom-name-else-"<Coin> #N" fallback buildAccountItems() uses
    // for the real Accounts list, so this shows whatever name the user
    // would actually recognize the account by.
    const char *custom = store::accountName(coin, (uint8_t)idx);
    if (custom[0] != '\0') {
      snprintf(body, sizeof(body), "%s", custom);
    } else {
      snprintf(body, sizeof(body), "%s %d", coinDisplayName(coin), idx);
    }
  } else {
    snprintf(body, sizeof(body), "%s", coinDisplayName(coin));
  }
  showStub("Derive Error", body);
}

// Non-blocking serial line reader — accumulates into g_serialBuf and returns
// true (with the completed line in `out`) when a newline arrives.
static String g_serialBuf;
static bool pollSerialLine(String& out) {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      out = g_serialBuf;
      g_serialBuf = "";
      out.trim();
      return out.length() > 0;
    }
    if (c != '\r') {
      g_serialBuf += c;
      if (g_serialBuf.length() > 4096) g_serialBuf = "";  // safety
    }
  }
  return false;
}

// Re-derive and echo address for every activated coin (index 0).
// Used by the app on connect to recover addresses after data wipe.
//
// This is a single blocking call — nothing else runs (including the
// AUTO_LOCK_MS check in loop(), which only runs between top-level loop()
// iterations) until it returns, so auto-lock structurally cannot fire
// mid-sync no matter how long this takes. The only user-visible feedback
// during that whole window is this screen, so it shows real "N/total"
// progress rather than a static "Syncing..." message — the app side has
// no way to show its own progress here either, since it won't see
// anything until each address line actually arrives.
static void handleSyncReq() {
  if (!g_unlocked) return;
  Serial.println("SYNC_START");
  if (ble::isConnected()) ble::sendLine("SYNC_START");
  uint8_t mask[store::COIN_MASK_BYTES];
  store::coinMaskBytes(mask);  // read once — avoids N NVS reads in loop

  uint16_t totalCoins = 0;
  for (uint8_t i = 0; i < COIN_COUNT; i++) {
    if ((mask[i / 8] >> (i % 8)) & 1u) totalCoins++;
  }
  uint16_t doneCoins = 0;

  for (uint8_t i = 0; i < COIN_COUNT; i++) {
    if (!((mask[i / 8] >> (i % 8)) & 1u)) continue;
    doneCoins++;
    // Same loading-bar look as "Adding Network" (ADDR_REQ) — but a real
    // percentage here, not a time-based estimate: doneCoins/totalCoins is
    // an actual, exact completion count, no animation task needed.
    char syncMsg[40];
    snprintf(syncMsg, sizeof(syncMsg), "Syncing %s", coinDisplayName(i));
    display.loading(syncMsg, (uint8_t)((uint32_t)doneCoins * 100 / totalCoins));
    g_recvCoin = i;
    uint8_t acctMask = store::coinAccountMask(i);
    if (acctMask == 0) acctMask = 0x01;  // always echo at least index 0
    for (uint8_t idx = 0; idx < 8; idx++) {
      if (!((acctMask >> idx) & 1u)) continue;
      g_recvIndex = idx;
      if (i == COIN_BTC) {
        wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase);
      }
      // LTC/DOGE derive addresses inline in updateReceive(); no pre-caching needed.
      updateReceive();
    }
  }
  Serial.println("SYNC_END");
  if (ble::isConnected()) ble::sendLine("SYNC_END");
}

// Handle a XPUB_REQ|SYMBOL command from the app.
// For secp256k1 coins: emits the account-level xpub (standard xpub format, BIP44/84 path).
// For ed25519 coins: emits the address at index 0 (no public child derivation on ed25519).
// Response: "XPUB_RESP|SYMBOL>" prefix line, then payload on the next line.
static void handleXpubReq(const String& symbol) {
  if (!g_unlocked) return;
  String result;

  if (symbol == "BTC") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    char path[32];
    snprintf(path, sizeof(path), "m/84h/0h/0h");
    result = wallet::accountXpubForPath(path);
    wallet::endReceive();
  } else if (symbol == "ETH" || symbol == "BNB" || symbol == "AVAX" ||
             symbol == "BASE" || symbol == "POL" || symbol == "CRO" ||
             symbol == "USDT" || symbol == "USDC" ||
             symbol == "OP"   || symbol == "ARB"  || symbol == "FTM" ||
             symbol == "ETC"  || symbol == "LINEA" ||
             symbol == "CELO" || symbol == "MNT" ||
             symbol == "HYPE" || symbol == "OKB"  || symbol == "KCS" ||
             symbol == "XDC"  || symbol == "FLR"  ||
             symbol == "BTT"  || symbol == "MON"  || symbol == "XTZ" ||
             symbol == "IOTA" || symbol == "S"    ||
             symbol == "XPL"  || symbol == "KAIA" || symbol == "M") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/60h/0h");
    wallet::endReceive();
  } else if (symbol == "LTC") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/84h/2h/0h");
    wallet::endReceive();
  } else if (symbol == "DOGE") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/3h/0h");
    wallet::endReceive();
  } else if (symbol == "DASH") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/5h/0h");
    wallet::endReceive();
  } else if (symbol == "DGB") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/84h/20h/0h");
    wallet::endReceive();
  } else if (symbol == "RVN") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/175h/0h");
    wallet::endReceive();
  } else if (symbol == "BCH") {
    // Standard BTC-format xpub, same as every other UTXO coin — the app
    // derives the CashAddr address locally from the shared secp256k1 pubkey.
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/145h/0h");
    wallet::endReceive();
  } else if (symbol == "XRP") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/144h/0h");
    wallet::endReceive();
  } else if (symbol == "ATOM" || symbol == "DYDX" || symbol == "AXL" || symbol == "BABY" || symbol == "TIA") {
    // Same m/44'/118'/0' path for the whole standard-secp256k1 Cosmos family —
    // only the bech32 HRP differs, computed app-side from this shared xpub.
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/118h/0h");
    wallet::endReceive();
  } else if (symbol == "TRX" || symbol == "USDTTRX" || symbol == "BTTTRX") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/195h/0h");
    wallet::endReceive();
  } else if (symbol == "DOT") {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/354h/0h");
    wallet::endReceive();
  } else if (symbol == "FIL") {
    // secp256k1, standard BIP32 public-child derivation — the app derives
    // any account index locally from this one xpub, same as ATOM/TRX/BTC.
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) return;
    result = wallet::accountXpubForPath("m/44h/461h/0h");
    wallet::endReceive();
  } else if (symbol == "SOL") {
    result = sol::address(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "XLM") {
    result = xlm::address(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "ADA") {
    result = ada::address(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "GRAM") {
    // Raw pubkey, not the hashed address — same reasoning as SUI/APT/ALGO
    // below: a TON address is a hash of a StateInit cell that embeds the
    // pubkey, not reversible, and the app needs the raw pubkey to build the
    // wallet's state_init on a first-ever outgoing transaction.
    result = ton::pubKeyHex(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "SUI") {
    // Raw pubkey, not the hashed address — Sui's serialized signature format
    // needs the pubkey, and (unlike SOL/XLM) the address can't be reversed
    // back into it since it's a Blake2b hash.
    result = sui::pubKeyHex(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "APT") {
    // Same reasoning as SUI — Aptos addresses are a SHA3-256 hash of the
    // pubkey, not reversible.
    result = apt::pubKeyHex(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "NEAR") {
    // NEAR's implicit-account address IS the pubkey hex — no hash, so (like
    // SOL/XLM) the address itself is all the app needs.
    result = near::address(g_entropy, g_entropyLen, g_passphrase, 0);
  } else if (symbol == "ALGO") {
    // Same reasoning as SUI/APT — Algorand addresses are a SHA-512/256 hash
    // of the pubkey, and the app already has SHA-512/256 available locally.
    result = algo::pubKeyHex(g_entropy, g_entropyLen, g_passphrase, 0);
  } else {
    return;
  }

  if (result.length() == 0) return;
  String respLine = "XPUB_RESP|" + symbol + ">";
  Serial.println(respLine);
  Serial.println(result);
  if (ble::isConnected()) {
    ble::sendLine(respLine);
    ble::sendLine(result);
  }
}

// ---- Loading-bar animation (My Sentinel "add network" screen) -------------
//
// Address derivation is one single, CPU-bound blocking call with no natural
// progress checkpoints inside it to hook a real percentage into — live-
// measured over USB serial: ~1.0s for BTC/ETH/XRP, ~2.15s for ADA, ~0.25s
// baseline for everything else. Instrumenting the vendored crypto derivation
// code itself with progress callbacks would mix UI concerns into security-
// critical, upstream-tracked crypto code, so instead a second, lightweight
// FreeRTOS task redraws the bar on a timer while the main task's (unmodified)
// derivation call proceeds. ESP32's tick-based scheduler preempts the main
// loop task for this even though that task never explicitly yields — a real,
// perceptible animation, not a single static draw.
//
// This task ONLY ever touches the display — never wallet/crypto state — and
// is always fully stopped (confirmed exited, not just signaled) before any
// other code draws to the display again, so there is never a chance of two
// tasks writing to the OLED/I2C bus at the same time.
static volatile bool g_animRunning     = false;
static TaskHandle_t  g_animTaskHandle  = nullptr;
static char          g_animMessage[40];   // fits "Adding NEAR Protocol Network" etc.
static uint32_t      g_animStartMs     = 0;
static uint32_t      g_animEstimateMs  = 900;

static void animTaskFn(void *) {
  while (g_animRunning) {
    uint32_t elapsed = millis() - g_animStartMs;
    // Crawls toward 90%, never claims 100% on its own — stopLoadingAnimation()
    // is the only place that draws 100%, and only once the real work is
    // actually done. A wrong estimateMs just makes the ramp feel a little
    // too fast or slow; it can never make the bar lie about being finished.
    uint32_t pct = (elapsed * 90) / g_animEstimateMs;
    if (pct > 90) pct = 90;
    display.loading(g_animMessage, (uint8_t)pct);
    vTaskDelay(pdMS_TO_TICKS(90));
  }
  g_animTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

static void startLoadingAnimation(const char *message, uint32_t estimateMs) {
  snprintf(g_animMessage, sizeof(g_animMessage), "%s", message);
  g_animEstimateMs = estimateMs;
  g_animStartMs    = millis();
  g_animRunning    = true;
  // Priority 2 (main loopTask runs at 1) so the scheduler always preempts
  // promptly the instant each vTaskDelay() period elapses, rather than
  // depending on round-robin fairness between equal-priority tasks for a
  // steady animation cadence. Stack (4096B) and the task itself are trivial
  // next to this device's ~265KB of free RAM.
  xTaskCreate(animTaskFn, "loadAnim", 4096, nullptr, 2, &g_animTaskHandle);
}

// Signals the task to stop and blocks (briefly, bounded) until it actually
// has, so the caller can safely draw to the display again immediately after
// this returns. Draws one final 100% frame first for a clean finish, then
// holds on it briefly so it's actually visible rather than flashing by.
static void stopLoadingAnimation() {
  g_animRunning = false;
  uint32_t waited = 0;
  while (g_animTaskHandle != nullptr && waited < 500) {
    delay(5);
    waited += 5;
  }
  display.loading(g_animMessage, 100);
  delay(1000);
}

// Handle an ADDR_REQ command body ("SYMBOL|index") from the app over any
// transport. Derives the address and echoes it. Does NOT change store::coin()
// so the device UI (menu, receive screen) stays on whatever coin the user last
// navigated to — only the activation bits are persisted.
static void handleAddrReq(const String& body) {
  if (!g_unlocked) return;
  int sep = body.indexOf('|');
  String sym = sep >= 0 ? body.substring(0, sep) : body;
  uint32_t idx = sep >= 0 ? (uint32_t)body.substring(sep + 1).toInt() : 0;
  uint8_t c   = coinFromSymbol(sym);
  g_recvCoin  = c;
  g_recvIndex = idx;
  char animMsg[40];
  snprintf(animMsg, sizeof(animMsg), "Adding %s Network", coinDisplayName(c));
  startLoadingAnimation(animMsg, (c == COIN_ADA) ? 2100 : 900);
  // For BTC, prime the HD key cache so updateReceive() can derive the address.
  if (c == COIN_BTC) {
    wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase);
  }
  store::activateCoin(c);
  store::activateAccountBit(c, (uint8_t)idx);
  updateReceive();  // derives address and echoes "addr #N SYMBOL: ..."
  stopLoadingAnimation();
}

// Like ADDR_REQ but for account discovery: derives and echoes the address with
// a "probe #N SYMBOL: <addr>" prefix so the app can check on-chain activity
// without activating the coin on the device or changing the displayed screen.
static void handleAddrProbe(const String& body) {
  if (!g_unlocked) return;
  int sep = body.indexOf('|');
  String sym = sep >= 0 ? body.substring(0, sep) : body;
  uint32_t idx = sep >= 0 ? (uint32_t)body.substring(sep + 1).toInt() : 0;
  uint8_t c = coinFromSymbol(sym);

  String addr;
  if (isSolFamily(c))
    addr = sol::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_XLM)
    addr = xlm::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_ADA)
    addr = ada::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_SUI)
    addr = sui::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_APT)
    addr = apt::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_NEAR)
    addr = near::address(g_entropy, g_entropyLen, g_passphrase, idx);
  else if (c == COIN_ALGO)
    addr = algo::address(g_entropy, g_entropyLen, g_passphrase, idx);

  if (addr.length() == 0) return;

  const char* tag = coinName(c);
  String line = String("probe #") + idx + " " + tag + ": " + addr;
  Serial.println(line);
  if (ble::isConnected()) ble::sendLine(line);
}

// App-initiated coin removal: "SYMBOL" — clears only the coin's own active
// bit (store::deactivateCoin), the same bit ADDR_REQ/handleAddrReq sets via
// store::activateCoin. Leaves naccts/account names/cached addresses alone,
// so a later ADDR_REQ for the same symbol (re-adding it) restores any
// previously-created accounts instead of starting over. If this was the
// currently on-screen coin, render()'s own SCREEN_MENU case already detects
// "selected coin no longer active" and jumps to another active coin (or
// "(none)") on the very next redraw — no extra handling needed here.
static void handleCoinDeactivate(const String& body) {
  if (!g_unlocked) return;
  store::deactivateCoin(coinFromSymbol(body));
}

// App-initiated account delete: "SYMBOL|INDEX"
static void handleAcctDelete(const String& body) {
  if (!g_unlocked) return;
  int sep = body.indexOf('|');
  if (sep < 0) return;
  String sym = body.substring(0, sep);
  uint8_t idx = (uint8_t)body.substring(sep + 1).toInt();
  uint8_t c = coinFromSymbol(sym);
  if (c >= COIN_COUNT) return;
  store::deactivateAccountBit(c, idx);
  store::clearAccountName(c, idx);
}

// App-initiated account rename: "SYMBOL|INDEX|NEW_NAME"
static void handleAcctRename(const String& body) {
  if (!g_unlocked) return;
  int sep1 = body.indexOf('|');
  if (sep1 < 0) return;
  String sym = body.substring(0, sep1);
  String rest = body.substring(sep1 + 1);
  int sep2 = rest.indexOf('|');
  if (sep2 < 0) return;
  uint8_t idx = (uint8_t)rest.substring(0, sep2).toInt();
  String name = rest.substring(sep2 + 1);
  uint8_t c = coinFromSymbol(sym);
  if (c >= COIN_COUNT) return;
  store::setAccountName(c, idx, name.c_str());
}

// Bitmask sync from app on reconnect: "SYMBOL|BITMASK"
// Rebuilds the account bitmask without address derivation.
static void handleAcctSync(const String& body) {
  if (!g_unlocked) return;
  int sep = body.indexOf('|');
  if (sep < 0) return;
  String sym = body.substring(0, sep);
  uint8_t incoming = (uint8_t)body.substring(sep + 1).toInt();
  uint8_t c = coinFromSymbol(sym);
  if (c >= COIN_COUNT) return;
  // OR with existing mask — never let the app remove accounts the device knows
  // about. Explicit deletion goes through ACCT_DELETE.
  store::setCoinAccountMask(c, store::coinAccountMask(c) | incoming);
  store::activateCoin(c);
}

// App-initiated sign-select: "SYMBOL" — the app is about to send a
// transaction for this coin and wants the user to confirm/open it on-device
// first (unified flow for every coin, PSBT-based or tagged: coin identity
// comes from this explicit signal, not from inferring it off the tx payload
// itself, which PSBT coins in particular carry no self-describing symbol
// for). Requires the coin to already be active (an account must already
// exist — same assumption ADDR_REQ's activation already established).
// store::coin() itself is NOT changed here; that only happens once the user
// approves on SCREEN_SIGN_SELECT.
static void handleSignSelect(const String& body) {
  if (!g_unlocked) return;
  uint8_t c = coinFromSymbol(body);
  if (c >= COIN_COUNT || !store::isCoinActive(c)) return;
  g_pendingSignCoin = c;
  screen = SCREEN_SIGN_SELECT;
}

static void doReceive() {
  buildAccountItems();   // populate g_acctCount / g_acctCoins / g_acctBipIndex
  if (g_acctCount > 1) {
    g_acctListSel = 0;
    screen = SCREEN_ACCOUNT_LIST;
    return;
  }
  display.message("QR Code", "Please wait...");
  if (store::coin() == COIN_BTC) {
    if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) {
      showDeriveError(store::coin(), -1);
      return;
    }
  }
  // LTC/DOGE derive addresses inline in updateReceive(); no pre-caching needed.
  // Use the single known account's coin+index; fall back to current coin at 0.
  g_recvCoin  = (g_acctCount == 1) ? g_acctCoins[0]    : store::coin();
  g_recvIndex = (g_acctCount == 1) ? g_acctBipIndex[0] : 0;
  updateReceive();
  if (g_recvAddr.length() == 0) { showDeriveError(g_recvCoin, (int)g_recvIndex); return; }
  display.qr(g_recvAddr.c_str());  // encode now; render loop just redraws the cache
  screen = SCREEN_RECEIVE_QR;
}

// Read one line of base64 from Serial. BACK cancels (returns ""). Caps length
// to avoid unbounded growth.
static String readSerialLineOrCancel() {
  String s;
  for (;;) {
    ButtonAction a;
    if (buttons.poll(a) && a.id == BTN_BACK) return String("");
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n' || c == '\r') { if (s.length() > 0) return s; }
      else {
        s += c;
        if (s.length() > 16384) return s;   // safety cap
      }
    }
    delay(2);
  }
}

// Parse a base64 PSBT and enter the on-device review flow. `src` records where
// the signed result should be returned. Pass `net` for alt-UTXO chains (LTC/DOGE);
// nullptr uses plain BTC mainnet.
static void startSignFromB64(const String &b64, SignSource src,
                              const Network *net = nullptr) {
  display.message("Sign Tx", "Parsing...");
  bool ok = signer::load(b64, g_entropy, g_entropyLen, g_passphrase, net ? net : &Mainnet);
  if (!ok) {
    display.message("Sign Tx", "Invalid PSBT");
    delay(1800);
    screen = SCREEN_MENU;
    return;
  }
  g_signSource = src;
  g_signPage = 0;
  screen = SCREEN_SIGN_REVIEW;
}


// True if the currently loaded transaction for coin `c` can only ever be
// reviewed as a blind-sign hash (no itemized decode) - matches exactly
// which render*Review() branches show "BLIND SIGN" per coldwallet.ino's
// own dispatch. SOL/XLM are conditional: they're itemized whenever the
// payload is a recognized transfer, blind-sign only in the fallback case.
static bool isBlindSignTx(uint8_t c) {
  switch (c) {
    case COIN_XRP: case COIN_ATOM: case COIN_DYDX: case COIN_AXL:
    case COIN_BABY: case COIN_TIA: case COIN_TRX: case COIN_TON:
    case COIN_DOT: case COIN_FIL: case COIN_SUI: case COIN_APT:
    case COIN_NEAR: case COIN_ALGO: case COIN_USDTTRX: case COIN_BTTTRX: case COIN_BCH:
    case COIN_ADA:
      return true;
    case COIN_SOL:
      return !sol::txHasTransfer();
    case COIN_XLM:
      return !xlm::txHasPayment();
    default:
      return false;  // PSBT coins (BTC/LTC/DOGE/DASH/DGB/RVN), EVM family
  }
}

static void doSign() {
  uint8_t c = store::coin();

  // Mirrors Ledger's own per-app "Blind signing" setting: a coin whose
  // review can only ever be a blind hash refuses to actually produce a
  // signature until the user has explicitly turned this on for it in
  // that coin's own Settings (off by default). The review screen itself
  // is unaffected — the user can still page through it — this only gates
  // the final hold-to-sign step, same as an ordinary sign failure.
  if (isBlindSignTx(c) && !store::isBlindSignAllowed(c)) {
    char body[48];
    snprintf(body, sizeof(body), "Enable in %s's\nSettings first", coinDisplayName(c));
    display.message("Blind sign off", body);
    delay(2000);
    screen = SCREEN_MENU;
    return;
  }

  display.message("Sign Tx", "Signing...");
  String out;
  bool ok;
  // String, not const char* — eth::txSignLabel() below returns an owned
  // String; storing just its c_str() here would dangle once that temporary
  // is destroyed, since label is used later in this function.
  String label = "PSBT-SIGNED>";

  if (c == COIN_ADA) {
    out = ada::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    // A delegation-certificate tx (flagged via loadTx()'s optional "STAKE"
    // field) needs a second witness from the stake key — appended here,
    // before clearTx(), against the same loaded tx/hash signTx() just used.
    // A plain transfer's response is completely unchanged (still exactly
    // vkey||sig, 192 hex chars) since needsStakeWitness() is false for it.
    if (ok && ada::needsStakeWitness()) {
      String stakeOut = ada::signTxStake(g_entropy, g_entropyLen, g_passphrase);
      ok = stakeOut.length() > 0;
      out += stakeOut;
    }
    ada::clearTx();
    label = "ADA-SIGNED>";
  } else if (c == COIN_XLM) {
    out = xlm::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    xlm::clearTx();
    label = "XLM-SIGNED>";
  } else if (isSolFamily(c)) {
    // Any SPL token transfer (recognized generically from the message
    // instructions, same as native SOL) signs and responds through this
    // exact path — no per-token id, see isSolFamily()'s comment.
    out = sol::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    sol::clearTx();
    label = "SOL-SIGNED>";
  } else if (isEvmCoin(c)) {
    // Any EVM chain or ERC-20/BEP-20 token transfer (recognized generically
    // from the payload by eth.cpp) signs through this one slot — the
    // response label is derived from the transaction itself (chainId, or
    // the token's contract address), not from which coin is selected here.
    // Must be read before clearTx() discards the loaded transaction state.
    label = eth::txSignLabel();
    out = eth::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    eth::clearTx();
  } else if (c == COIN_XRP) {
    // Read before clearTx() discards the loaded tx state — same reasoning
    // as eth::txSignLabel() above. RLUSD/TrustSet (and any future XRPL
    // issued currency) sign under this same COIN_XRP slot; only the wire
    // tag ("XRP"/"XRPT"/"XRPTRUST") distinguished which shape was loaded.
    bool issued = xrp::isIssuedTx();
    bool trustSet = xrp::isTrustSetTx();
    out = xrp::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    xrp::clearTx();
    label = trustSet ? "TRUSTSET-SIGNED>" : issued ? "RLUSD-SIGNED>" : "XRP-SIGNED>";
  } else if (c == COIN_ATOM || c == COIN_DYDX || c == COIN_AXL || c == COIN_BABY || c == COIN_TIA) {
    out = cosmos::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    cosmos::clearTx();
    label = (c == COIN_DYDX) ? "DYDX-SIG>" :
            (c == COIN_AXL)  ? "AXL-SIG>"  :
            (c == COIN_BABY) ? "BABY-SIG>" :
            (c == COIN_TIA)  ? "TIA-SIG>"  : "ATOM-SIG>";
  } else if (c == COIN_TRX) {
    out = tron::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    tron::clearTx();
    label = "TRX-SIG>";
  } else if (c == COIN_TON) {
    out = ton::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    ton::clearTx();
    label = "GRAM-SIG>";
  } else if (c == COIN_DOT) {
    out = dot::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    dot::clearTx();
    label = "DOT-SIG>";
  } else if (c == COIN_FIL) {
    out = fil::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    fil::clearTx();
    label = "FIL-SIG>";
  } else if (c == COIN_SUI) {
    out = sui::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    sui::clearTx();
    label = "SUI-SIG>";
  } else if (c == COIN_APT) {
    out = apt::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    apt::clearTx();
    label = "APT-SIG>";
  } else if (c == COIN_NEAR) {
    out = near::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    near::clearTx();
    label = "NEAR-SIG>";
  } else if (c == COIN_ALGO) {
    out = algo::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    algo::clearTx();
    label = "ALGO-SIG>";
  } else if (c == COIN_USDTTRX) {
    out = tron::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    tron::clearTx();
    label = "USDTTRX-SIG>";
  } else if (c == COIN_BTTTRX) {
    out = tron::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    tron::clearTx();
    label = "BTTTRX-SIG>";
  } else if (c == COIN_BCH) {
    // Parallel signing path, not PSBT — see bch.h for why.
    out = bch::signTx(g_entropy, g_entropyLen, g_passphrase);
    ok = out.length() > 0;
    bch::clearTx();
    label = "BCH-SIGNED>";
  } else {
    // BTC / LTC / DOGE / DASH / DGB / RVN — PSBT signing
    label = (c == COIN_LTC)  ? "LTC-SIGNED>"  :
            (c == COIN_DOGE) ? "DOGE-SIGNED>" :
            (c == COIN_DASH) ? "DASH-SIGNED>" :
            (c == COIN_DGB)  ? "DGB-SIGNED>"  :
            (c == COIN_RVN)  ? "RVN-SIGNED>"  : "PSBT-SIGNED>";
    int n = signer::sign(g_entropy, g_entropyLen, g_passphrase, out);
    ok = (n > 0);
    signer::clear();
  }

  if (!ok) {
    out = "";
    display.message("Sign Tx", "Sign failed");
    delay(2000);
    screen = SCREEN_MENU;
    return;
  }

  Serial.println(label);
  Serial.println(out);      // signed tx (public data — safe on serial)
  if (g_signSource == SRC_BLE) ble::sendLine(out);
  out = "";
  display.message("Signed OK", g_signSource == SRC_BLE ? "sent via BLE" : "see serial");
  screen = SCREEN_SIGN_DONE;
}


static void doToggleBle() {
  bool on = !store::bleEnabled();
  store::setBleEnabled(on);
  if (on) ble::enable(BLE_DEVICE_NAME);
  else    ble::disable();
}

static void doResetWallet() {
  uint8_t lg = store::language();
  if (!confirmModal(i18n::tr(lg, i18n::S_RESET_DEVICE), i18n::tr(lg, i18n::S_HOLD_OK_RESET_DEVICE),
                     /*centered=*/true)) return;

  // Require PIN confirmation before the destructive wipe.
  char pin[PIN_MAX_DIGITS + 1];
  pin[0] = '\0';
  int n = pinEntryModal(i18n::tr(lg, i18n::S_CONFIRM_PIN), pin, PIN_MAX_DIGITS, false);
  if (n < 0) {
    wallet::zeroize(pin, sizeof(pin));
    display.message(i18n::tr(lg, i18n::S_CANCELLED), i18n::tr(lg, i18n::S_RESET_ABORTED));
    delay(1200);
    return;
  }

  uint8_t dummy_entropy[64];
  char    dummy_pass[store::MAX_PASSPHRASE + 1];
  size_t  dummy_len = 0;
  uint8_t left      = 0;
  store::LoadResult r = store::loadSeed(pin, dummy_entropy, &dummy_len,
                                        dummy_pass, sizeof(dummy_pass), &left);
  wallet::zeroize(pin,          sizeof(pin));
  wallet::zeroize(dummy_entropy, sizeof(dummy_entropy));
  wallet::zeroize(dummy_pass,   sizeof(dummy_pass));

  if (r != store::LOAD_OK) {
    display.message(i18n::tr(lg, i18n::S_WRONG_PIN), i18n::tr(lg, i18n::S_RESET_CANCELLED));
    delay(1800);
    return;
  }

  // PIN verified — wipe everything and reboot to factory state.
  ble::disable();
  store::wipe();
  lockWallet();
  display.message(i18n::tr(lg, i18n::S_RESET), i18n::tr(lg, i18n::S_DEVICE_ERASED_REBOOTING));
  delay(1500);
  ESP.restart();
}

static void doUninstallAllCoins() {
  uint8_t lg = store::language();
  if (!confirmModal(i18n::tr(lg, i18n::S_UNINSTALL_ALL_COINS), i18n::tr(lg, i18n::S_HOLD_OK_UNINSTALL_ALL),
                     /*centered=*/true)) return;
  for (uint8_t i = 0; i < COIN_COUNT; i++) store::deactivateCoin(i);
  display.message(i18n::tr(lg, i18n::S_UNINSTALLED), i18n::tr(lg, i18n::S_ALL_COINS_REMOVED));
  delay(1200);
}

// Verifies the current PIN like doResetWallet() does, but — unlike Reset —
// keeps the real decrypted entropy+passphrase (not dummy buffers) so they
// can be re-encrypted under a new PIN via store::saveSeed() rather than
// discarded.
static void doChangePin() {
  uint8_t lg = store::language();
  if (!confirmModal(i18n::tr(lg, i18n::S_CHANGE_PIN), i18n::tr(lg, i18n::S_HOLD_OK_SET_NEW_PIN),
                     /*centered=*/true)) return;

  char oldPin[PIN_MAX_DIGITS + 1];
  oldPin[0] = '\0';
  int n = pinEntryModal(i18n::tr(lg, i18n::S_CURRENT_PIN), oldPin, PIN_MAX_DIGITS, false);
  if (n < 0) {
    wallet::zeroize(oldPin, sizeof(oldPin));
    display.message(i18n::tr(lg, i18n::S_CANCELLED), i18n::tr(lg, i18n::S_PIN_UNCHANGED));
    delay(1200);
    return;
  }

  uint8_t entropy[64];
  char    passphrase[store::MAX_PASSPHRASE + 1];
  size_t  entLen = 0;
  uint8_t left   = 0;
  store::LoadResult r = store::loadSeed(oldPin, entropy, &entLen,
                                        passphrase, sizeof(passphrase), &left);
  wallet::zeroize(oldPin, sizeof(oldPin));

  if (r != store::LOAD_OK) {
    wallet::zeroize(entropy, sizeof(entropy));
    wallet::zeroize(passphrase, sizeof(passphrase));
    display.message(i18n::tr(lg, i18n::S_WRONG_PIN), i18n::tr(lg, i18n::S_PIN_UNCHANGED));
    delay(1800);
    return;
  }

  // Collect + confirm the new PIN, mirroring firstRunFlow()'s own loop.
  char newPin[PIN_MAX_DIGITS + 1];
  newPin[0] = '\0';
  bool ok = false;
  for (;;) {
    int n1 = pinEntryModal(i18n::tr(lg, i18n::S_NEW_PIN), newPin, PIN_MAX_DIGITS, false);
    if (n1 < 0) {
      wallet::zeroize(newPin, sizeof(newPin));
      break;
    }
    char p2[PIN_MAX_DIGITS + 1];
    p2[0] = '\0';
    int n2 = pinEntryModal(i18n::tr(lg, i18n::S_CONFIRM_PIN), p2, PIN_MAX_DIGITS, false);
    bool match = (n2 >= 0) && (strcmp(newPin, p2) == 0);
    wallet::zeroize(p2, sizeof(p2));
    if (!match) {
      wallet::zeroize(newPin, sizeof(newPin));
      display.message(i18n::tr(lg, i18n::S_MISMATCH), i18n::tr(lg, i18n::S_TRY_AGAIN));
      delay(1500);
      continue;
    }
    ok = true;
    break;
  }

  if (ok) ok = store::saveSeed(entropy, entLen, passphrase, newPin);
  wallet::zeroize(entropy, sizeof(entropy));
  wallet::zeroize(passphrase, sizeof(passphrase));
  wallet::zeroize(newPin, sizeof(newPin));

  display.message(ok ? i18n::tr(lg, i18n::S_PIN_CHANGED) : i18n::tr(lg, i18n::S_CANCELLED),
                   ok ? i18n::tr(lg, i18n::S_NEW_PIN_SAVED) : i18n::tr(lg, i18n::S_PIN_UNCHANGED));
  delay(1200);
}

// ---- DEV preview-only clones (serial debug tool, see DEV_SCREEN/DEV_MODAL) --
// These render the exact same screens as their real counterparts above, for
// visual review without physically walking to the real trigger - but MUST
// NEVER call store::loadSeed()/wipe()/deactivateCoin()/saveSeed(). Those
// functions have real side effects on this device's real wallet (loadSeed()
// alone consumes a real wrong-PIN attempt even just to check a PIN, wipe()
// erases everything, deactivateCoin() really deactivates). Reusing the real
// doResetWallet()/doChangePin()/doUninstallAllCoins()/firstRunFlow()
// functions directly for "preview" would risk real, hard-to-undo damage to
// the device under review - these are independent, side-effect-free clones
// instead, using only pinEntryModal()/confirmModal()/display.message() and
// throwaway buffers that are never checked against real storage.
static void devPreviewPin(const char *title) {
  char dummy[PIN_MAX_DIGITS + 1];
  dummy[0] = '\0';
  pinEntryModal(title, dummy, PIN_MAX_DIGITS, false);
  wallet::zeroize(dummy, sizeof(dummy));
  screen = SCREEN_MENU;
}

// Cosmetic-only preview of the home menu's Coin slot in its "no coin
// installed yet" state ("+" icon, "Install Coins" label) - draws directly
// rather than going through the real anyCoinActive() check, so it can be
// reviewed without actually uninstalling every real coin on the device.
static void devPreviewEmptyHomeMenu() {
  display.homeMenu(0, "+", i18n::tr(store::language(), i18n::S_INSTALL_COINS),
                   ble::isEnabled(), ble::isConnected(),
                   g_usbAppConnected, g_batteryPct, /*showCoinArrows=*/false);
  waitButton();
  screen = SCREEN_MENU;
}

static void devPreviewWelcome() {
  display.message("Sentinel Wallet", "Hold OK to begin\nthe setup", /*centered=*/true);
  for (;;) {
    ButtonAction a = waitButton();
    if (a.id == BTN_SELECT) break;   // either a tap or a hold starts setup
  }
  screen = SCREEN_MENU;
}

// Real, valid, publicly-known BIP39 test-vector mnemonic - safe to display
// since it's never converted to entropy or saved anywhere.
static const char *kDevDummyMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon "
  "abandon abandon abandon abandon abandon abandon abandon abandon "
  "abandon abandon abandon abandon abandon abandon abandon art";

// The pre-generation "Important" warning sequence - 4 pages, title always
// "Important" (not all-caps), navigated by Left/Right only (edge-pinned
// triangle arrows, same visual language as the seed word pages) rather
// than tapping OK to advance. Holding OK on the last page ("Hold OK to
// continue") is what actually proceeds past the sequence.
static const char *const kImportantPages[4] = {
  "Write down your\nseed phrase",
  "Your 24-word\nrecovery phrase\nwill be generated\nnow",
  "This is your only\nbackup, don't lose\nit or share with\nother people",
  "Hold OK to\ncontinue",
};

// `idx` is in/out so the caller's position survives a back-out and a later
// return to this step. Returns true once finished (hold-SEL on the last
// page), false if the user backed out from the first page (go to the
// previous wizard step) - a long-press on Back does that instantly from
// any page, a short press just steps back one page at a time (same as Left).
static bool showImportantSequence(uint8_t &idx) {
  for (;;) {
    bool isFirst = (idx == 0);
    bool isLast  = (idx == 3);
    display.importantPage("Important", kImportantPages[idx], !isFirst, !isLast);

    ButtonAction a = waitButton();
    if      (a.id == BTN_LEFT  && !isFirst) idx--;
    else if (a.id == BTN_RIGHT && !isLast)  idx++;
    else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS && isLast) return true;
    else if (a.id == BTN_BACK && a.event == EV_LONGPRESS) return false;
    else if (a.id == BTN_BACK) { if (!isFirst) idx--; else return false; }
  }
}

// Same in/out-index + back-navigation shape as showImportantSequence(),
// for the real (non-preview) 24-word backup review used by firstRunFlow().
// Returns true once finished (hold-SEL on the last word), false if the
// user backed out from the first word (go to the previous wizard step -
// the Important sequence's last page).
static bool seedReviewLoop(uint8_t &idx) {
  for (;;) {
    bool isFirst = (idx == 0);
    bool isLast  = (idx + 1 == g_seedCount);
    char title[20];
    snprintf(title, sizeof(title), "Word %u / %u", idx + 1, g_seedCount);
    display.seedWordPage(title, g_seedWords[idx].c_str(), !isFirst, !isLast, isLast);

    ButtonAction a = waitButton();
    if      (a.id == BTN_LEFT  && !isFirst) idx--;
    else if (a.id == BTN_RIGHT && !isLast)  idx++;
    else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS && isLast) return true;
    else if (a.id == BTN_BACK && a.event == EV_LONGPRESS) return false;
    else if (a.id == BTN_BACK) { if (!isFirst) idx--; else return false; }
  }
}

// Modal: verify one seed word by multiple choice rather than re-typing it -
// shows the real word plus 3 random decoys from the full BIP39 wordlist
// (distinct from the real word and from each other), shuffled so the
// correct one isn't always in the same slot, as a plain list (same shape/
// selection behaviour as chooseWordCountModal - Up/Down move the cursor, a
// short SEL press picks, no on-screen instructions needed). Returns 1 if
// the correct word was picked, 0 if a wrong one was, or -1 if the user
// backed out.
static int verifyWordChoiceModal(uint8_t pos, uint8_t total, const char *correctWord) {
  static const uint8_t kOptions = 4;
  int totalWords = 0;
  wallet::wordlistMatch("", &totalWords);   // empty prefix matches every word - gives the count (2048)

  const char *opts[kOptions];
  opts[0] = correctWord;
  uint8_t filled = 1;
  while (filled < kOptions) {
    const char *cand = wallet::wordlistAt(esp_random() % totalWords);
    bool dup = false;
    for (uint8_t i = 0; i < filled; i++) {
      if (strcmp(opts[i], cand) == 0) { dup = true; break; }
    }
    if (!dup) opts[filled++] = cand;
  }
  for (uint8_t i = kOptions - 1; i > 0; i--) {   // Fisher-Yates shuffle
    uint8_t j = esp_random() % (i + 1);
    const char *tmp = opts[i]; opts[i] = opts[j]; opts[j] = tmp;
  }

  char title[20];
  snprintf(title, sizeof(title), "Verify %u/%u", pos, total);
  uint8_t sel = 0;
  for (;;) {
    display.menu(title, opts, kOptions, sel);
    ButtonAction a = waitButton();
    if      (a.id == BTN_UP)   sel = (sel == 0) ? kOptions - 1 : sel - 1;
    else if (a.id == BTN_DOWN) sel = (sel + 1) % kOptions;
    else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
      return (strcmp(opts[sel], correctWord) == 0) ? 1 : 0;
    }
    else if (a.id == BTN_BACK) return -1;
  }
}

// Returns false if the user backed out early (caller should bail without
// showing a completion message).
static bool devPreviewWordLoop() {
  uint8_t wordIdx = 0;
  bool doneReading = false;
  while (!doneReading) {
    bool isFirst = (wordIdx == 0);
    bool isLast  = (wordIdx + 1 == g_seedCount);
    char title[20];
    snprintf(title, sizeof(title), "Word %u / %u", wordIdx + 1, g_seedCount);
    display.seedWordPage(title, g_seedWords[wordIdx].c_str(), !isFirst, !isLast, isLast);

    ButtonAction a = waitButton();
    // Physical Left = Prev, physical Right = Next - matches the on-screen
    // label positions (Prev bottom-left, Next/Done bottom-right). Finishing
    // is still hold-OK (the center SELECT button), same as before - the
    // "Done" label on the last page is informational, not bound to Right.
    if      (a.id == BTN_LEFT  && !isFirst) wordIdx--;
    else if (a.id == BTN_RIGHT && !isLast)  wordIdx++;
    else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS && isLast) doneReading = true;
    else if (a.id == BTN_BACK) { clearSeedState(); screen = SCREEN_MENU; return false; }
  }
  return true;
}

// Cosmetic-only preview of the post-generation backup check (never calls
// store::saveSeed()) - mirrors firstRunFlow()'s STEP_SEED_VERIFY exactly
// so it can be reviewed without wiping the real device. Goes through every
// word in order (word 1 -> word g_seedCount), not a random subset.
static bool devPreviewVerifyLoop() {
  uint8_t i = 0;
  while (i < g_seedCount) {
    int result = verifyWordChoiceModal(i + 1, g_seedCount, g_seedWords[i].c_str());
    if (result < 0) {
      if (i == 0) { clearSeedState(); screen = SCREEN_MENU; return false; }
      i--;
      continue;
    }
    if (result == 0) {
      display.message("Verify", "That's not the\nright word - check\nyour backup");
      delay(2200);
      continue;   // stay on this same word - a fresh reshuffled choice next loop
    }
    i++;
  }
  return true;
}

static void devPreviewSeedFlow() {
  uint8_t idx = 0;
  if (!showImportantSequence(idx)) { screen = SCREEN_MENU; return; }

  splitMnemonic(String(kDevDummyMnemonic));   // only fills g_seedWords/g_seedCount in RAM
  if (!devPreviewWordLoop()) return;
  if (!devPreviewVerifyLoop()) return;

  // Cosmetic only - never actually calls store::saveSeed().
  display.centeredMessage("Setup done");
  delay(1400);
  clearSeedState();
  screen = SCREEN_MENU;
}

// Skips straight to the word-by-word pages (no intro sequence) - a quicker
// way to re-review just this part without re-tapping through 4 intro pages.
static void devPreviewWordsOnly() {
  splitMnemonic(String(kDevDummyMnemonic));
  if (!devPreviewWordLoop()) return;
  if (!devPreviewVerifyLoop()) return;
  clearSeedState();
  screen = SCREEN_MENU;
}

// Skips straight to the backup-check pages (no intro, no word-by-word
// review) - the fastest way to re-review just this new part on its own.
static void devPreviewVerifyOnly() {
  splitMnemonic(String(kDevDummyMnemonic));
  if (!devPreviewVerifyLoop()) return;
  display.centeredMessage("Setup done");
  delay(1400);
  clearSeedState();
  screen = SCREEN_MENU;
}

// Restore-flow preview: word-count picker -> real word entry (via the same
// enterWordModal() the real restore flow uses) -> checksum check -> cosmetic
// result. Never calls store::saveSeed() - the whole point is to review the
// screens, not restore a real wallet over this device's real one.
static void devPreviewRestoreFlow() {
  int wc = chooseWordCountModal();
  if (wc == 0) { screen = SCREEN_MENU; return; }   // BK

  clearSeedState();
  for (uint8_t i = 0; i < (uint8_t)wc; i++) {
    int idx = enterWordModal(i + 1, (uint8_t)wc);
    if (idx < 0) { clearSeedState(); screen = SCREEN_MENU; return; }
    g_seedWords[i] = wallet::wordlistAt(idx);
    g_seedCount = i + 1;
  }

  String m;
  for (uint8_t i = 0; i < g_seedCount; i++) { if (i) m += ' '; m += g_seedWords[i]; }
  bool valid = wallet::validateMnemonic(m);
  m = "";
  display.centeredMessage(valid ? "Setup done" : "Bad checksum");
  delay(1600);
  clearSeedState();
  screen = SCREEN_MENU;
}

static void devPreviewChangePin() {
  if (!confirmModal("Change PIN", "Hold OK to set\na new PIN", /*centered=*/true)) { screen = SCREEN_MENU; return; }

  char dummy[PIN_MAX_DIGITS + 1];
  dummy[0] = '\0';
  int n = pinEntryModal("Current PIN", dummy, PIN_MAX_DIGITS, false);
  wallet::zeroize(dummy, sizeof(dummy));
  if (n < 0) {
    display.message("Cancelled", "PIN unchanged");
    delay(1200);
    screen = SCREEN_MENU;
    return;
  }

  for (;;) {
    char p1[PIN_MAX_DIGITS + 1];
    p1[0] = '\0';
    int n1 = pinEntryModal("New PIN", p1, PIN_MAX_DIGITS, false);
    if (n1 < 0) {
      wallet::zeroize(p1, sizeof(p1));
      display.message("Cancelled", "PIN unchanged");
      delay(1200);
      screen = SCREEN_MENU;
      return;
    }
    char p2[PIN_MAX_DIGITS + 1];
    p2[0] = '\0';
    int n2 = pinEntryModal("Confirm PIN", p2, PIN_MAX_DIGITS, false);
    bool match = (n2 >= 0) && (strcmp(p1, p2) == 0);
    wallet::zeroize(p1, sizeof(p1));
    wallet::zeroize(p2, sizeof(p2));
    if (!match) {
      display.message("Mismatch", "try again");
      delay(1500);
      continue;
    }
    break;
  }

  // Cosmetic only - never actually calls store::saveSeed().
  display.message("PIN Changed", "New PIN saved");
  delay(1200);
  screen = SCREEN_MENU;
}

static void devPreviewResetDevice() {
  if (!confirmModal("Reset Device", "Hold OK to reset\nyour device", /*centered=*/true)) { screen = SCREEN_MENU; return; }

  char dummy[PIN_MAX_DIGITS + 1];
  dummy[0] = '\0';
  int n = pinEntryModal("Confirm PIN", dummy, PIN_MAX_DIGITS, false);
  wallet::zeroize(dummy, sizeof(dummy));
  if (n < 0) {
    display.message("Cancelled", "Reset aborted");
    delay(1200);
    screen = SCREEN_MENU;
    return;
  }

  // Cosmetic only - never actually calls store::wipe()/ESP.restart().
  display.message("Reset", "Device erased\nRebooting...");
  delay(1500);
  screen = SCREEN_MENU;
}

static void devPreviewUninstallAllCoins() {
  if (!confirmModal("Uninstall All Coins", "Hold OK to uninstall\nall coins from the\ndevice", /*centered=*/true)) { screen = SCREEN_MENU; return; }
  // Cosmetic only - never actually calls store::deactivateCoin().
  display.message("Uninstalled", "All coins removed");
  delay(1200);
  screen = SCREEN_MENU;
}

// ---- Rendering --------------------------------------------------------------
static void renderEthReview() {
  if (g_signPage == 0) {
    // Page 0: what + how much.
    String body = eth::txAmountStr() + " " + eth::txSymbol() + "\n\nDn=recipient";
    String title = eth::txIsErc20() ? String("Send token") : ("Send " + eth::txSymbol());
    display.message(title.c_str(), body.c_str());
  } else if (g_signPage == 1) {
    // Page 1: the recipient address, wrapped.
    String body;
    String r = eth::txRecipient();
    const int W = 21;
    for (int i = 0; i < (int)r.length(); i += W) {
      body += r.substring(i, min(i + W, (int)r.length()));
      body += "\n";
    }
    display.message("Recipient", body.c_str());
  } else {
    // Page 2: fee + chain + confirm.
    String body = "Fee<=" + eth::txFeeStr() + " " + eth::txNativeSymbol() + "\nChain: " +
                  String((unsigned long)eth::txChainId()) + "\nhold SEL=SIGN\nBK=cancel";
    display.message("Confirm", body.c_str());
  }
}

static void renderSolReview() {
  const char *ticker = coinName(store::coin());   // "SOL" or an SPL family member (e.g. "JUP")
  if (g_signPage == 0) {
    if (sol::txHasTransfer()) {
      String title = String("Send ") + ticker;
      String body = sol::txAmountStr() + " SOL\n\nDn=recipient";
      display.message(title.c_str(), body.c_str());
    } else {
      String title = String("Sign ") + ticker;
      char body[48];
      snprintf(body, sizeof(body), "BLIND SIGN\n%lu bytes\nverify on host",
               (unsigned long)sol::txMsgLen());
      display.message(title.c_str(), body);
    }
  } else if (g_signPage == 1 && sol::txHasTransfer()) {
    String body;
    String r = sol::txRecipient();
    const int W = 21;
    for (int i = 0; i < (int)r.length(); i += W) {
      body += r.substring(i, min(i + W, (int)r.length()));
      body += "\n";
    }
    display.message("Recipient", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderXlmReview() {
  if (g_signPage == 0) {
    if (xlm::txHasPayment()) {
      String body = xlm::txAmountStr() + " XLM\n\nDn=recipient";
      display.message("Send XLM", body.c_str());
    } else {
      String body = "BLIND SIGN\nhash: " + xlm::txHashHex() + "\nverify on host";
      display.message("Sign XLM", body.c_str());
    }
  } else if (g_signPage == 1 && xlm::txHasPayment()) {
    String body;
    String r = xlm::txRecipient();
    const int W = 21;
    for (int i = 0; i < (int)r.length(); i += W) {
      body += r.substring(i, min(i + W, (int)r.length()));
      body += "\n";
    }
    display.message("Recipient", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderAdaReview() {
  // ADA on-device CBOR output display is a future enhancement; blind-sign for now.
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nhash: " + ada::txHashHex() + "\nverify on host";
    display.message("Sign ADA", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderXrpReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nhash: " + xrp::txHashHex() + "..\nverify on host";
    const char *title = xrp::isTrustSetTx() ? "Trust Line"
                       : xrp::isIssuedTx()   ? "Sign RLUSD"
                                              : "Sign XRP";
    display.message(title, body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderCosmosReview() {
  if (g_signPage == 0) {
    String title = String("Sign ") + coinName(store::coin());
    String body = "BLIND SIGN\nhash: " + cosmos::txHashHex() + "..\nverify on host";
    display.message(title.c_str(), body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderTronReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nhash: " + tron::txHashHex() + "..\nverify on host";
    display.message("Sign TRX", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderTonReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nhash: " + ton::txHashHex() + "..\nverify on host";
    display.message("Sign GRAM", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderDotReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + dot::txHashHex() + "..\nverify on host";
    display.message("Sign DOT", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderFilReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + fil::txHashHex() + "..\nverify on host";
    display.message("Sign FIL", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderSuiReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + sui::txHashHex() + "..\nverify on host";
    display.message("Sign SUI", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderAptReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + apt::txHashHex() + "..\nverify on host";
    display.message("Sign APT", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderNearReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + near::txHashHex() + "..\nverify on host";
    display.message("Sign NEAR", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderAlgoReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + algo::txHashHex() + "..\nverify on host";
    display.message("Sign ALGO", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderBchReview() {
  if (g_signPage == 0) {
    String body = "BLIND SIGN\nbytes: " + bch::txHashHex() + "..\nverify on host";
    display.message("Sign BCH", body.c_str());
  } else {
    display.message("Confirm", "hold SEL=SIGN\nBK=cancel");
  }
}

static void renderSignReview() {
  if (store::coin() == COIN_ADA) { renderAdaReview(); return; }
  if (store::coin() == COIN_XLM) { renderXlmReview(); return; }
  if (isSolFamily(store::coin())) { renderSolReview(); return; }
  if (isEvmCoin(store::coin())) { renderEthReview(); return; }
  if (store::coin() == COIN_XRP) { renderXrpReview(); return; }
  if (store::coin() == COIN_ATOM || store::coin() == COIN_DYDX ||
      store::coin() == COIN_AXL  || store::coin() == COIN_BABY ||
      store::coin() == COIN_TIA) { renderCosmosReview(); return; }
  if (store::coin() == COIN_TRX) { renderTronReview(); return; }
  if (store::coin() == COIN_TON) { renderTonReview(); return; }
  if (store::coin() == COIN_DOT) { renderDotReview(); return; }
  if (store::coin() == COIN_FIL) { renderFilReview(); return; }
  if (store::coin() == COIN_SUI) { renderSuiReview(); return; }
  if (store::coin() == COIN_APT) { renderAptReview(); return; }
  if (store::coin() == COIN_NEAR) { renderNearReview(); return; }
  if (store::coin() == COIN_ALGO) { renderAlgoReview(); return; }
  if (store::coin() == COIN_BCH) { renderBchReview(); return; }
  if (store::coin() == COIN_USDTTRX) { renderTronReview(); return; }
  if (store::coin() == COIN_BTTTRX) { renderTronReview(); return; }
  uint8_t nOut = signer::storedOutputs();
  if (g_signPage < nOut) {
    // One output per page: amount, change tag, and wrapped address.
    char title[24];
    snprintf(title, sizeof(title), "Out %u/%u%s",
             g_signPage + 1, signer::totalOutputs(),
             signer::outputIsMine(g_signPage) ? " chg" : "");
    String body = satToBtc(signer::outputAmountSat(g_signPage)) + " " + coinName(store::coin()) + "\n";
    const char *addr = signer::outputAddress(g_signPage);
    const int W = 21;
    for (int i = 0; i < (int)strlen(addr); i += W) {
      body += String(addr).substring(i, min(i + W, (int)strlen(addr)));
      body += "\n";
    }
    display.message(title, body.c_str());
  } else {
    // Summary / confirm page - also shows the primary (non-change)
    // recipient's amount + a shortened address, not just the fee alone.
    String body = "";
    int mainOut = -1;
    for (uint8_t i = 0; i < nOut; i++) {
      if (!signer::outputIsMine(i)) { mainOut = i; break; }
    }
    if (mainOut >= 0) {
      body += satToBtc(signer::outputAmountSat((uint8_t)mainOut)) + " " + coinName(store::coin()) + "\n";
      body += shortenAddr(signer::outputAddress((uint8_t)mainOut)) + "\n";
    }
    body += "Fee: " + satToBtc(signer::feeSat()) + "\n";
    if (signer::truncated()) body += "(+more outs)\n";
    body += "Hold OK to confirm";
    display.message("Confirm", body.c_str());
  }
}

static void renderAccountList() {
  buildAccountItems();
  char title[24];
  snprintf(title, sizeof(title), "%s Accounts", coinLabel(store::coin()));
  display.menu(title, g_acctPtrs, g_acctCount, g_acctListSel);
}

static void render() {
  switch (screen) {
    case SCREEN_MENU: {
      uint8_t mask[store::COIN_MASK_BYTES];
      store::coinMaskBytes(mask);
      bool anyActive = false;
      for (size_t i = 0; i < store::COIN_MASK_BYTES; i++) {
        if (mask[i]) { anyActive = true; break; }
      }
      uint8_t activeCount = 0;
      for (uint8_t i = 0; i < COIN_COUNT; i++) {
        if ((mask[i / 8] >> (i % 8)) & 1u) activeCount++;
      }
      uint8_t  c    = store::coin();
      if (anyActive && !store::isCoinActive(c)) {
        for (uint8_t i = 0; i < COIN_COUNT; i++) {
          if ((mask[i / 8] >> (i % 8)) & 1u) { c = i; store::setCoin(c); break; }
        }
      }
      uint8_t lg = store::language();
      const char *ticker      = anyActive ? coinLabel(c) : "+";
      const char *displayName = anyActive ? coinDisplayName(c) : i18n::tr(lg, i18n::S_INSTALL_COINS);
      char batteryLabel[32];
      snprintf(batteryLabel, sizeof(batteryLabel), "%s %u%%", i18n::tr(lg, i18n::S_BATTERY), (unsigned)g_batteryPct);
      const char *labels[5]   = { displayName, i18n::tr(lg, i18n::S_LOCK_DEVICE),
                                   i18n::tr(lg, i18n::S_SETTINGS), batteryLabel,
                                   i18n::tr(lg, i18n::S_POWER_OFF) };
      display.homeMenu(selected, ticker, labels[selected],
                       ble::isEnabled(), ble::isConnected(), g_usbAppConnected, g_batteryPct,
                       activeCount >= 2);
      break;
    }
    case SCREEN_SETTINGS:    buildSettings();
                             display.settingsMenu(i18n::tr(store::language(), i18n::S_SETTINGS),
                                                  settingsRows, kSettingsCount, settingsSel); break;
    case SCREEN_RECEIVE_QR:   display.qr(g_recvAddr.c_str()); break;
    case SCREEN_ACCOUNT_LIST: renderAccountList(); break;
    case SCREEN_SIGN_REVIEW:  renderSignReview(); break;
    case SCREEN_SIGN_DONE:    display.centeredMessage("Signed successfully"); break;
    case SCREEN_COIN_READY: {
      char body[32];
      snprintf(body, sizeof(body), "%s is ready", coinDisplayName(store::coin()));
      display.coinReady(coinLabel(store::coin()), body);
      break;
    }
    case SCREEN_COIN_MENU:
      display.arrowMenu(coinMenuItems(), coinMenuCount(), g_coinMenuSel);
      break;
    case SCREEN_COIN_SETTINGS: {
      // Only reachable via the coin-menu's "Settings" item, which itself
      // only appears when coinHasBlindSignSetting() is true - so this is
      // never entered for a coin without a real setting to show.
      buildCoinSettings();
      char csTitle[24];
      snprintf(csTitle, sizeof(csTitle), "%s Settings", coinSettingsTitleName(store::coin()));
      display.settingsMenu(csTitle, coinSettingsRows,
                           kCoinSettingsCount, g_coinSettingsSel);
      break;
    }
    case SCREEN_COIN_ABOUT:
      // Version is a fixed placeholder, same for every coin, for now.
      display.coinPrompt(coinLabel(store::coin()), "v1.0.0", "", "");
      break;
    case SCREEN_BATTERY_SAVER: {
      buildBatterySaverLabels();
      uint8_t cur = store::autoLockMinutes();
      uint8_t activeIdx = 0xFF;
      for (uint8_t i = 0; i < kBatterySaverCount; i++) {
        if (kBatterySaverMinutes[i] == cur) { activeIdx = i; break; }
      }
      display.menu(i18n::tr(store::language(), i18n::S_BATTERY_SAVER), kBatterySaverLabels,
                   kBatterySaverCount, g_batterySaverSel, activeIdx);
      break;
    }
    case SCREEN_LANGUAGE:
      display.menu("Language", kLanguageLabels, kLanguageCount, g_languageSel, store::language());
      break;
    case SCREEN_DEVICE_INFO:
      display.message("Device Info", deviceInfoBody);
      break;
    case SCREEN_SIGN_SELECT: {
      char title[32];
      snprintf(title, sizeof(title), "Open %s", coinDisplayName(g_pendingSignCoin));
      display.coinPrompt(coinLabel(g_pendingSignCoin), title, "to sign a transaction",
                         "Press OK to proceed");
      break;
    }
    case SCREEN_STUB:
      if (stubCentered) display.centeredMessage(stubBody);
      else              display.message(stubTitle, stubBody);
      break;
  }
}

// Wait (OLED already blanked by the caller) until any button is pressed, then
// return so the caller can wake the screen.
//
// NOTE: this is a plain polling wait, NOT CPU light sleep. The esp_light_sleep_
// start() path was removed because it caused a reboot after unlocking — the
// light-sleep -> heavy-crypto/NVS (PBKDF2 + AES-GCM in loadSeed) path crashes on
// the C5. The OLED-off already saves most of the idle power; restoring true CPU
// light sleep needs a proper fix (see the panic backtrace) before it's safe.
static void waitForWakeButton() {
  ButtonAction a;
  while (buttons.poll(a)) { }           // drain any stale events
  while (!buttons.poll(a)) delay(10);   // stay here (screen dark) until a press
}

// ---- Auto-lock --------------------------------------------------------------
// ---- First-run setup flow ---------------------------------------------------
// Runs when there is no stored seed (new device or after Reset Wallet).
// Blocking — never returns until a seed is saved and the wallet is unlocked.
// The whole first-boot wizard is one linear sequence of steps (Welcome ->
// Setup picker -> PIN -> [Restore: word count -> word entry] or [New
// device: warning pages -> seed review] -> done). Back always means "go to
// the previous step in this sequence" - a plain step index + switch (rather
// than nested loops returning sentinel values, the earlier shape) is what
// makes that uniform, since any step can be reached by going either
// forward or backward from its neighbours. Per-step state (savedPin, the
// picker's cursor, the word-count toggle, which word/page we're on) lives
// in locals at this function's scope precisely so it survives a step back
// and a step forward again - e.g. Set PIN shows whatever digits were
// already typed, a restore word shows the word that was already picked
// for it.
static void firstRunFlow() {
  enum Step {
    STEP_WELCOME,
    STEP_PICKER,
    STEP_PIN_SET,
    STEP_PIN_CONFIRM,
    STEP_WORDCOUNT,     // restore path only
    STEP_WORD_ENTRY,    // restore path only
    STEP_IMPORTANT,     // new-device path only
    STEP_SEED_REVIEW,   // new-device path only
    STEP_SEED_VERIFY,   // new-device path only
  };
  Step step = STEP_WELCOME;

  uint8_t setupSel = 0;
  bool    restoring = false;

  char savedPin[PIN_MAX_DIGITS + 1];
  savedPin[0] = '\0';

  int     wc = 24;
  uint8_t wordEntryIdx = 0;

  uint8_t importantIdx = 0;
  uint8_t reviewWordIdx = 0;

  // Post-generation backup check: every word, in order, before the seed is
  // actually saved - each is a fast multiple-choice pick (verifyWordChoiceModal),
  // not a re-type, so checking all of them isn't the tedium full re-entry
  // would be.
  uint8_t verifyIdx = 0;

  for (;;) {
    switch (step) {

    case STEP_WELCOME: {
      display.message("Sentinel Wallet", "Hold OK to begin\nthe setup", /*centered=*/true);
      ButtonAction a = waitButton();
      if (a.id == BTN_SELECT) step = STEP_PICKER;
      // No step before Welcome - Back here is simply ignored.
      break;
    }

    case STEP_PICKER: {
      int sel = chooseSetupPath(setupSel);
      if (sel < 0) { step = STEP_WELCOME; break; }
      setupSel  = (uint8_t)sel;
      restoring = (sel == 1);
      step = STEP_PIN_SET;
      break;
    }

    case STEP_PIN_SET: {
      int n1 = pinEntryModal("Set PIN", savedPin, PIN_MAX_DIGITS, false);
      if (n1 < 0) { step = STEP_PICKER; break; }
      step = STEP_PIN_CONFIRM;
      break;
    }

    case STEP_PIN_CONFIRM: {
      char p2[PIN_MAX_DIGITS + 1];
      p2[0] = '\0';
      int n2 = pinEntryModal("Confirm PIN", p2, PIN_MAX_DIGITS, false);
      if (n2 < 0) { step = STEP_PIN_SET; break; }   // back - savedPin stays as typed
      bool match = (strcmp(savedPin, p2) == 0);
      wallet::zeroize(p2, sizeof(p2));
      if (!match) {
        display.message("Mismatch", "try again");
        delay(1500);
        savedPin[0] = '\0';   // a genuine mismatch really does start the PIN over
        step = STEP_PIN_SET;
        break;
      }
      step = restoring ? STEP_WORDCOUNT : STEP_IMPORTANT;
      break;
    }

    case STEP_WORDCOUNT: {
      int w = chooseWordCountModal(wc);
      // Back here skips both PIN screens entirely and returns straight to
      // the New Device / Restore picker - PIN entry and the seed-phrase
      // stage are treated as two separate stages, not steps to walk back
      // through one at a time. Since PIN entry is being skipped rather
      // than walked back through, the typed PIN is discarded, not kept -
      // it must be re-entered in full if the user comes back this way.
      if (w == 0) {
        wallet::zeroize(savedPin, sizeof(savedPin));
        savedPin[0] = '\0';
        step = STEP_PICKER;
        break;
      }
      wc = w;
      clearSeedState();
      wordEntryIdx = 0;
      step = STEP_WORD_ENTRY;
      break;
    }

    case STEP_WORD_ENTRY: {
      const char *initial = (wordEntryIdx < g_seedCount) ? g_seedWords[wordEntryIdx].c_str() : nullptr;
      int idx = enterWordModal(wordEntryIdx + 1, (uint8_t)wc, initial);
      if (idx < 0) {
        if (wordEntryIdx == 0) { step = STEP_WORDCOUNT; break; }
        wordEntryIdx--;   // back to the previous word, prefilled with what was picked
        break;
      }
      g_seedWords[wordEntryIdx] = wallet::wordlistAt(idx);
      if (g_seedCount < wordEntryIdx + 1) g_seedCount = wordEntryIdx + 1;
      wordEntryIdx++;

      if (wordEntryIdx < (uint8_t)wc) break;   // more words to go

      // All words entered - validate the BIP39 checksum before accepting.
      g_seedCount = (uint8_t)wc;
      String m;
      for (uint8_t i = 0; i < g_seedCount; i++) { if (i) m += ' '; m += g_seedWords[i]; }
      bool valid = wallet::validateMnemonic(m);
      m = "";
      if (!valid) {
        display.message("Restore", "Bad checksum\ncheck words");
        delay(2200);
        wordEntryIdx = (uint8_t)wc - 1;   // let them fix any word via Back from here
        break;
      }

      bool ok = doSaveSeedAndUnlock(savedPin);
      wallet::zeroize(savedPin, sizeof(savedPin));
      clearSeedState();
      if (!ok) {
        display.centeredMessage("Setup failed");
        delay(1500);
        return;
      }
      display.centeredMessage("Setup done");
      delay(1400);
      return;
    }

    case STEP_IMPORTANT: {
      bool finished = showImportantSequence(importantIdx);
      // Same reasoning as STEP_WORDCOUNT's own back above - skip both PIN
      // screens and discard the typed PIN, go straight to the picker.
      if (!finished) {
        wallet::zeroize(savedPin, sizeof(savedPin));
        savedPin[0] = '\0';
        step = STEP_PICKER;
        break;
      }

      if (g_seedCount == 0) {   // generate the seed once, first time through
        String phrase = wallet::generateSeedPhrase(24);
        if (phrase.length() == 0 || !wallet::validateMnemonic(phrase)) {
          wallet::zeroize(savedPin, sizeof(savedPin));
          Serial.println("FATAL: seed generation failed");
          display.message("Error", "RNG failed\nRestart device");
          for (;;) delay(100);
        }
        splitMnemonic(phrase);
        phrase = "";
        reviewWordIdx = 0;
      }
      step = STEP_SEED_REVIEW;
      break;
    }

    case STEP_SEED_REVIEW: {
      bool finished = seedReviewLoop(reviewWordIdx);
      if (!finished) { step = STEP_IMPORTANT; break; }   // back from word 0

      // Don't save yet - make the user prove they actually wrote the
      // words down first, one at a time in order.
      verifyIdx = 0;
      step = STEP_SEED_VERIFY;
      break;
    }

    case STEP_SEED_VERIFY: {
      int result = verifyWordChoiceModal(verifyIdx + 1, g_seedCount, g_seedWords[verifyIdx].c_str());
      if (result < 0) {
        if (verifyIdx == 0) { step = STEP_SEED_REVIEW; break; }   // back to the review
        verifyIdx--;
        break;
      }
      if (result == 0) {
        display.message("Verify", "That's not the\nright word - check\nyour backup");
        delay(2200);
        break;   // stay on this same word - a fresh reshuffled choice next loop
      }
      verifyIdx++;
      if (verifyIdx < g_seedCount) break;   // more words to check

      bool ok = doSaveSeedAndUnlock(savedPin);
      if (ok) {
        display.centeredMessage("Setup done");
        delay(1400);
        wallet::zeroize(savedPin, sizeof(savedPin));
        clearSeedState();
        return;
      }
      display.centeredMessage("Setup failed");
      delay(1500);
      // Rare (storage failure) - retry is a single hold-OK away, not a
      // full re-check.
      verifyIdx = g_seedCount - 1;
      break;
    }
    }
  }
}

// Called from loop() after AUTO_LOCK_MS of inactivity. Wipes the keys from RAM,
// turns BLE off, blanks the OLED for low power, and stays dark until a button
// wakes it — then blocks on the PIN screen until the user unlocks again.
static void autoLock() {
  g_usbAppConnected = false;      // reset connection indicators on lock
  ble::disable();                 // turn the radio off while locked (security)
  lockWallet();                   // zeroize entropy/passphrase; g_unlocked = false
  display.message("Locked", "Idle timeout");
  delay(700);

  display.sleep();                // OLED off — low-power idle
  waitForWakeButton();            // stay dark until any button is pressed
  display.wake();                 // OLED back on

  if (store::hasSeed()) {
    unlockFlow();                 // blocks until re-unlocked (or wiped)
  }
  // Restore BLE per the saved setting once unlocked again (mirrors boot).
  if (g_unlocked && store::bleEnabled()) ble::enable(BLE_DEVICE_NAME);

  selected = 0;
  settingsSel = 0;
  screen = SCREEN_MENU;
  g_lastActivityMs = millis();
  render();
}

// ---- Setup / loop -----------------------------------------------------------
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(50);
  Serial.println();
  Serial.println(FW_NAME " " FW_VERSION " — Phase 6 (optional BLE)");

  display.begin();
  buttons.begin();
  display.splash(FW_NAME, "");
  store::migrateIfNeeded();
  display.setLanguage(store::language());

  g_batteryPct = 60 + (esp_random() % 41);   // placeholder 60-100%, see g_batteryPct's own comment

  // Diagnostic: verify HD derivation against the public BIP84 test vector.
  {
    String got;
    bool ok = wallet::selfTestBip84(&got);
    Serial.print("bip84 self-test (idx0 | idx1): "); Serial.println(ok ? "PASS" : "FAIL");
    Serial.print("  got: "); Serial.println(got);
    Serial.println("  exp: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu | bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
  }

  delay(800);

  if (store::hasSeed()) {
    Serial.println("wallet present — unlocking");
    unlockFlow();       // blocks until unlocked or wiped
  } else {
    Serial.println("no wallet — first run setup");
    firstRunFlow();     // blocks until seed saved + PIN set
  }

  // BLE only comes up after a successful unlock, and only if enabled.
  ble::begin();
  if (g_unlocked && store::bleEnabled()) {
    ble::enable(BLE_DEVICE_NAME);
    Serial.println("BLE enabled (advertising)");
  }

  g_lastActivityMs = millis();   // start the inactivity clock fresh
  render();
}

void loop() {
  // Auto-lock: after AUTO_LOCK_MS with no interaction, re-lock and return to the
  // PIN screen (BLE is turned off inside autoLock). Unsigned subtraction handles
  // millis() rollover correctly.
  if (g_unlocked && (uint32_t)(millis() - g_lastActivityMs) >= autoLockMs()) {
    autoLock();
    return;
  }

  // Accept BLE commands. PAIR is handled regardless of lock state — the
  // physical button confirmation on the device is the security mechanism.
  // Transaction signing is only allowed while unlocked at the menu.
  if (ble::isConnected()) {
    String line;
    if (ble::takePsbt(line)) {

      if (line.startsWith("PAIR|")) {
        // PIN pairing — app generates the code, shows it to the user, sends it
        // here. We display it on-screen so the user can compare, then confirm
        // or reject with a long-press of OK / any other button.
        String code = line.substring(5);
        char body[48];
        snprintf(body, sizeof(body), "Code: %s\nHold OK: pair\nBack: reject", code.c_str());
        display.message("Pair request", body);
        ButtonAction a = waitButton();
        if (a.id == BTN_SELECT && a.event == EV_LONGPRESS) {
          ble::sendLine("PAIR-OK>");
          display.message("Paired!", "Sentinel linked");
          delay(800);
        } else {
          ble::sendLine("PAIR-FAIL>");
          display.message("Pair", "Rejected");
          delay(800);
        }
        render();
        return;
      }

      // App-initiated address generation (any screen, unlocked).
      if (g_unlocked && line.startsWith("ADDR_REQ|")) {
        g_lastActivityMs = millis();
        handleAddrReq(line.substring(9));
        // Real bug this fixes: unlike every other handler in this dispatch
        // (the Serial equivalent falls through to its own render() call;
        // COIN_REMOVE/PAIR above call it explicitly), this one returned
        // immediately after handleAddrReq() with no render() at all — so
        // the loading screen's final 100% frame just stayed on-screen
        // forever instead of the normal screen (menu/receive/etc.) resuming.
        render();
        return;
      }

      // Silent probe for account discovery — no activateCoin(), no screen change.
      if (g_unlocked && line.startsWith("ADDR_PROBE|")) {
        // Was missing from every other authenticated command's pattern —
        // a real multi-round-trip discovery scan (dozens of probes in a
        // row) never counted as activity, so it could run right into the
        // auto-lock timer firing mid-scan and killing the connection.
        g_lastActivityMs = millis();
        handleAddrProbe(line.substring(11));
        return;
      }

      if (g_unlocked && line.startsWith("SIGN_SELECT|")) {
        g_lastActivityMs = millis();
        g_signSelectSource = SRC_BLE;
        handleSignSelect(line.substring(12));
        render();
        return;
      }

      if (g_unlocked && line.startsWith("ACCT_DELETE|")) {
        handleAcctDelete(line.substring(12));
        return;
      }

      if (g_unlocked && line.startsWith("COIN_REMOVE|")) {
        handleCoinDeactivate(line.substring(12));
        render();
        return;
      }

      if (g_unlocked && line.startsWith("ACCT_RENAME|")) {
        handleAcctRename(line.substring(12));
        return;
      }

      if (g_unlocked && line.startsWith("ACCT_SYNC|")) {
        handleAcctSync(line.substring(10));
        return;
      }

      if (g_unlocked && line == "SYNC_REQ") {
        g_lastActivityMs = millis();
        handleSyncReq();
        render();
        return;
      }

      if (g_unlocked && line.startsWith("XPUB_REQ|")) {
        g_lastActivityMs = millis();
        handleXpubReq(line.substring(9));
        return;
      }

      if (line == "HELLO") {
        if (g_unlocked) { g_lastActivityMs = millis(); notifyReady(); }
        return;
      }

      if (g_unlocked && screen == SCREEN_MENU) {
        g_lastActivityMs = millis();
        uint8_t c = store::coin();
        if (isEvmCoin(c)) {
          if (eth::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_XRP) {
          if (xrp::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_ATOM) {
          if (cosmos::loadTx(line, "ATOM")) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_DYDX) {
          if (cosmos::loadTx(line, "DYDX")) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_AXL) {
          if (cosmos::loadTx(line, "AXL")) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_BABY) {
          if (cosmos::loadTx(line, "BABY")) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_TIA) {
          if (cosmos::loadTx(line, "TIA")) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_TRX) {
          if (tron::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_TON) {
          if (ton::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_DOT) {
          if (dot::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_FIL) {
          if (fil::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_SUI) {
          if (sui::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_APT) {
          if (apt::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_NEAR) {
          if (near::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_ALGO) {
          if (algo::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_BCH) {
          if (bch::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_USDTTRX || c == COIN_BTTTRX) {
          if (tron::loadTxForTag(String(coinName(c)), line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (isSolFamily(c)) {
          if (sol::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_XLM) {
          if (xlm::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_ADA) {
          if (ada::loadTx(line)) { g_signSource = SRC_BLE; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        } else if (c == COIN_BTC) {
          // All PSBTs base64-encode to strings starting with "cHNidP" (magic psbt\xff).
          // Silently ignore anything else to prevent stray BLE lines triggering this path.
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE);
        } else if (c == COIN_LTC) {
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE, &LtcMainnet);
        } else if (c == COIN_DOGE) {
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE, &DogeMainnet);
        } else if (c == COIN_DASH) {
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE, &DashMainnet);
        } else if (c == COIN_DGB) {
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE, &DgbMainnet);
        } else if (c == COIN_RVN) {
          if (line.startsWith("cHNidP")) startSignFromB64(line, SRC_BLE, &RvnMainnet);
        }
        render();
      }
      return;
    }
  }

  // Non-blocking serial poll — handles commands from the app over USB.
  {
    String serialLine;
    if (pollSerialLine(serialLine)) {
      if (serialLine == "HELLO") {
        g_usbAppConnected = true;
        if (g_unlocked) notifyReady();
      } else if (g_unlocked && serialLine.startsWith("DEV_SCREEN|")) {
        g_lastActivityMs = millis();   // a jump counts as activity, same as every real command
        // Serial-only debug jump: renders a Screen directly, skipping
        // normal navigation - a workflow convenience for reviewing screen
        // layouts one by one without walking the real menu tree each time.
        // Not part of the app-facing wire protocol, never reachable over
        // BLE. Only fabricates state for the couple of screens that would
        // otherwise show nothing meaningful (RECEIVE_QR's address,
        // SIGN_SELECT's pending coin, DEVICE_INFO's body text) - everything
        // else just renders whatever real state happens to already exist.
        String name = serialLine.substring(11);
        if (name == "MENU")              screen = SCREEN_MENU;
        else if (name == "MENU_EMPTY")   devPreviewEmptyHomeMenu();
        else if (name == "SETTINGS")     { settingsSel = 0; screen = SCREEN_SETTINGS; }
        else if (name == "BATTERY_SAVER") screen = SCREEN_BATTERY_SAVER;
        else if (name == "LANGUAGE")     screen = SCREEN_LANGUAGE;
        else if (name == "DEVICE_INFO") {
          snprintf(deviceInfoBody, sizeof(deviceInfoBody), "%s\nID: %04X\n%s %s\n%s",
                   BLE_DEVICE_NAME, (unsigned)store::deviceId(),
                   i18n::tr(store::language(), i18n::S_FIRMWARE), FW_VERSION, "sentinelwallet.io");
          screen = SCREEN_DEVICE_INFO;
        }
        else if (name == "COIN_READY")   screen = SCREEN_COIN_READY;
        else if (name == "COIN_MENU")    { g_coinMenuSel = 0; screen = SCREEN_COIN_MENU; }
        else if (name == "COIN_SETTINGS") { g_coinSettingsSel = 0; screen = SCREEN_COIN_SETTINGS; }
        else if (name == "COIN_ABOUT")   screen = SCREEN_COIN_ABOUT;
        else if (name == "SIGN_SELECT")  { g_pendingSignCoin = store::coin(); screen = SCREEN_SIGN_SELECT; }
        else if (name == "SIGN_REVIEW")  { g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
        else if (name == "SIGN_DONE")    screen = SCREEN_SIGN_DONE;
        else if (name == "ACCOUNT_LIST") screen = SCREEN_ACCOUNT_LIST;
        else if (name == "RECEIVE_QR") {
          if (g_recvAddr.length() == 0) g_recvAddr = "placeholder-address-preview";
          screen = SCREEN_RECEIVE_QR;
        }
        else if (name == "STUB")         screen = SCREEN_STUB;
        // Every distinct message SCREEN_STUB is ever shown with in real
        // use (deduplicated down to the 2 actually-distinct title/body
        // pairs remaining) - lets each be previewed directly without
        // walking to its real trigger.
        else if (name == "STUB_0")       showDeriveError(store::coin(), 0);
        else if (name == "STUB_1")       showStub("Receive", "Add coins via\nthe Sentinel app");
        // PIN entry / setup / seed-phrase / destructive-action previews -
        // all of these are blocking modal loops, not simple Screen jumps,
        // so control doesn't return here (and the OK echo below doesn't
        // print) until the user finishes interacting with the real device.
        // See the devPreview*() functions themselves for why these are
        // side-effect-free clones rather than calls into the real
        // doResetWallet()/doChangePin()/doUninstallAllCoins()/firstRunFlow().
        else if (name == "SPLASH_PREVIEW") {
          display.splash(FW_NAME, "");
          waitButton();
          screen = SCREEN_MENU;
        }
        else if (name == "PIN_PREVIEW_ENTER")   devPreviewPin("Enter PIN");
        else if (name == "PIN_PREVIEW_SET")     devPreviewPin("Set PIN");
        else if (name == "PIN_PREVIEW_CONFIRM") devPreviewPin("Confirm PIN");
        else if (name == "PIN_PREVIEW_CURRENT") devPreviewPin("Current PIN");
        else if (name == "PIN_PREVIEW_NEW")     devPreviewPin("New PIN");
        else if (name == "PIN_WRONG_MSG") {
          display.message("Denied", "Wrong PIN\n3 tries left");
          waitButton();   // stays up until a real button press, not a fixed delay
          screen = SCREEN_MENU;
        }
        else if (name == "PIN_WIPED_MSG") {
          display.message("Wiped", "Too many tries");
          waitButton();
          screen = SCREEN_MENU;
        }
        else if (name == "WELCOME_PREVIEW")     devPreviewWelcome();
        else if (name == "SEEDGEN_PREVIEW")     devPreviewSeedFlow();
        else if (name == "WORDS_ONLY_PREVIEW")  devPreviewWordsOnly();
        else if (name == "VERIFY_PREVIEW")      devPreviewVerifyOnly();
        // Restore-flow screens - each of these is pure UI (pick a path /
        // word count / word), never a call into store::saveSeed()/wipe(),
        // so the real functions are safe to preview directly.
        else if (name == "SETUP_PICKER_PREVIEW") { chooseSetupPath(); screen = SCREEN_MENU; }
        else if (name == "WORDCOUNT_PREVIEW")    { chooseWordCountModal(); screen = SCREEN_MENU; }
        else if (name == "ENTERWORD_PREVIEW")    { enterWordModal(1, 24); screen = SCREEN_MENU; }
        else if (name == "RESTORE_FLOW_PREVIEW") devPreviewRestoreFlow();
        else if (name == "SETUP_DONE_MSG") {
          display.centeredMessage("Setup done");
          waitButton();
          screen = SCREEN_MENU;
        }
        else if (name == "SETUP_FAIL_MSG") {
          display.centeredMessage("Setup failed");
          waitButton();
          screen = SCREEN_MENU;
        }
        else if (name == "CHANGEPIN_PREVIEW")   devPreviewChangePin();
        else if (name == "RESET_PREVIEW")       devPreviewResetDevice();
        else if (name == "UNINSTALL_PREVIEW")   devPreviewUninstallAllCoins();
        render();
        Serial.print("DEV_SCREEN_OK|"); Serial.println((int)screen);
      } else if (g_unlocked) {
        g_lastActivityMs = millis();
        if (serialLine.startsWith("ADDR_REQ|")) {
          handleAddrReq(serialLine.substring(9));
        } else if (serialLine.startsWith("ADDR_PROBE|")) {
          handleAddrProbe(serialLine.substring(11));
          return;
        } else if (serialLine.startsWith("SIGN_SELECT|")) {
          g_signSelectSource = SRC_SERIAL;
          handleSignSelect(serialLine.substring(12));
          render();
          return;
        } else if (serialLine.startsWith("ACCT_DELETE|")) {
          handleAcctDelete(serialLine.substring(12));
          return;
        } else if (serialLine.startsWith("COIN_REMOVE|")) {
          handleCoinDeactivate(serialLine.substring(12));
          render();
          return;
        } else if (serialLine.startsWith("ACCT_RENAME|")) {
          handleAcctRename(serialLine.substring(12));
          return;
        } else if (serialLine.startsWith("ACCT_SYNC|")) {
          handleAcctSync(serialLine.substring(10));
          return;
        } else if (serialLine == "SYNC_REQ") {
          handleSyncReq();
        } else if (serialLine.startsWith("XPUB_REQ|")) {
          handleXpubReq(serialLine.substring(9));
          return;
        } else if (screen == SCREEN_MENU) {
          // App-initiated signing over USB — mirrors the BLE signing fallthrough.
          uint8_t c = store::coin();
          if (isEvmCoin(c)) {
            if (eth::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_XRP) {
            if (xrp::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_ATOM) {
            if (cosmos::loadTx(serialLine, "ATOM")) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_DYDX) {
            if (cosmos::loadTx(serialLine, "DYDX")) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_AXL) {
            if (cosmos::loadTx(serialLine, "AXL")) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_BABY) {
            if (cosmos::loadTx(serialLine, "BABY")) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_TIA) {
            if (cosmos::loadTx(serialLine, "TIA")) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_TRX) {
            if (tron::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_TON) {
            if (ton::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_DOT) {
            if (dot::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_FIL) {
            if (fil::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_SUI) {
            if (sui::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_APT) {
            if (apt::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_NEAR) {
            if (near::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_ALGO) {
            if (algo::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_BCH) {
            if (bch::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_USDTTRX || c == COIN_BTTTRX) {
            if (tron::loadTxForTag(String(coinName(c)), serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (isSolFamily(c)) {
            if (sol::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_XLM) {
            if (xlm::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_ADA) {
            if (ada::loadTx(serialLine)) { g_signSource = SRC_SERIAL; g_signPage = 0; screen = SCREEN_SIGN_REVIEW; }
          } else if (c == COIN_BTC) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL);
          } else if (c == COIN_LTC) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL, &LtcMainnet);
          } else if (c == COIN_DOGE) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL, &DogeMainnet);
          } else if (c == COIN_DASH) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL, &DashMainnet);
          } else if (c == COIN_DGB) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL, &DgbMainnet);
          } else if (c == COIN_RVN) {
            if (serialLine.startsWith("cHNidP")) startSignFromB64(serialLine, SRC_SERIAL, &RvnMainnet);
          }
        }
        render();
      }
    }
  }

  // Emit SENTINEL_READY when a BLE client connects while wallet is already unlocked.
  if (g_unlocked && ble::justConnected()) {
    g_usbAppConnected = false;
    notifyReady();   // instant — fp cached at unlock; sends SENTINEL_READY
    render();        // update home menu to show BLE indicator
  }

  ButtonAction a;
  if (!buttons.poll(a)) { delay(2); return; }
  g_lastActivityMs = millis();   // any button press resets the inactivity clock

  switch (screen) {
    case SCREEN_MENU:
      // LEFT/RIGHT navigate between icon slots.
      if (a.id == BTN_RIGHT) selected = (selected == 0) ? 4 : selected - 1;
      if (a.id == BTN_LEFT)  selected = (selected + 1) % 5;
      // UP/DOWN cycle active coins while on the Coin slot.
      if (selected == 0 && store::anyCoinActive()) {
        if (a.id == BTN_UP)   store::setCoin(prevCoin(store::coin()));
        if (a.id == BTN_DOWN) store::setCoin(nextCoin(store::coin()));
      }
      if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        switch (selected) {
          case 0:
            if (!store::anyCoinActive())
              showStub("Receive", "Add coins via\nthe Sentinel app");
            else
              // Was doReceive() (straight to the address/QR flow) - now just
              // a "<Coin> is ready" acknowledgement; QR/receive is left
              // wired up (doReceive(), SCREEN_RECEIVE_QR) but unreachable
              // from here for now, to be brought back later.
              screen = SCREEN_COIN_READY;
            break;
          case 1: autoLock(); break;
          case 2: settingsSel = 0; screen = SCREEN_SETTINGS; break;
          case 3: break;   // Battery — informational only, opens nothing
          case 4: break;   // Power Off — not wired up yet (needs a real battery first)
        }
      }
      break;

    case SCREEN_COIN_READY:
      if (a.id == BTN_DOWN) { g_coinMenuSel = 0; screen = SCREEN_COIN_MENU; }
      else if (a.id == BTN_BACK) { screen = SCREEN_MENU; }
      break;

    case SCREEN_COIN_MENU:
      if (a.id == BTN_UP) {
        if (g_coinMenuSel == 0) screen = SCREEN_COIN_READY;
        else g_coinMenuSel--;
      } else if (a.id == BTN_DOWN) {
        if (g_coinMenuSel + 1 < coinMenuCount()) g_coinMenuSel++;
      } else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        bool hasSettings = coinHasBlindSignSetting(store::coin());
        if (g_coinMenuSel == 0) {
          // No "no coins active" guard needed here — reaching the Coin Menu
          // at all requires having already passed through Coin Ready, which
          // itself only opens when anyCoinActive() is true (see SCREEN_MENU's
          // own Coin-slot handler).
          doReceive();
        } else if (hasSettings && g_coinMenuSel == 1) {
          g_coinSettingsSel = 0;
          screen = SCREEN_COIN_SETTINGS;
        } else {
          // "About" - always the last item, whichever index that is.
          screen = SCREEN_COIN_ABOUT;
        }
      } else if (a.id == BTN_BACK) {
        screen = SCREEN_MENU;
      }
      break;

    case SCREEN_COIN_ABOUT:
      if (a.id == BTN_BACK) screen = SCREEN_MENU;
      break;

    case SCREEN_COIN_SETTINGS:
      if (a.id == BTN_BACK) {
        screen = SCREEN_MENU;
      } else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        if (g_coinSettingsSel == 0) {
          uint8_t c = store::coin();
          bool newVal = !store::isBlindSignAllowed(c);
          buildCoinSettings();  // rows reflect the current, pre-toggle state
          char csTitle[24];
          snprintf(csTitle, sizeof(csTitle), "%s Settings", coinSettingsTitleName(c));
          animateToggleRow(csTitle, coinSettingsRows,
                           kCoinSettingsCount, g_coinSettingsSel, newVal);
          store::setBlindSignAllowed(c, newVal);
        }
      }
      break;

    case SCREEN_SIGN_SELECT:
      if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        store::setCoin(g_pendingSignCoin);
        Serial.println("SIGN_SELECT_OK>");
        if (g_signSelectSource == SRC_BLE) ble::sendLine("SIGN_SELECT_OK>");
        screen = SCREEN_MENU;
      } else if (a.id == BTN_BACK) {
        Serial.println("SIGN_SELECT_CANCEL>");
        if (g_signSelectSource == SRC_BLE) ble::sendLine("SIGN_SELECT_CANCEL>");
        screen = SCREEN_MENU;
      }
      break;

    case SCREEN_SETTINGS:
      if (a.id == BTN_UP)   settingsSel = (settingsSel == 0) ? kSettingsCount - 1 : settingsSel - 1;
      if (a.id == BTN_DOWN) settingsSel = (settingsSel + 1) % kSettingsCount;
      if (a.id == BTN_BACK) screen = SCREEN_MENU;
      if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        switch (settingsSel) {
          case 0: {   // Bluetooth
            bool newVal = !store::bleEnabled();
            buildSettings();  // rows reflect the current, pre-toggle state
            animateToggleRow("Settings", settingsRows, kSettingsCount,
                             settingsSel, newVal);
            doToggleBle();
            break;
          }
          case 1: {   // Battery Saver
            uint8_t cur = store::autoLockMinutes();
            g_batterySaverSel = 0;
            for (uint8_t i = 0; i < kBatterySaverCount; i++) {
              if (kBatterySaverMinutes[i] == cur) { g_batterySaverSel = i; break; }
            }
            screen = SCREEN_BATTERY_SAVER;
            break;
          }
          case 2: {   // Language
            g_languageSel = store::language();
            if (g_languageSel >= kLanguageCount) g_languageSel = 0;
            screen = SCREEN_LANGUAGE;
            break;
          }
          case 3: {   // Device Information
            snprintf(deviceInfoBody, sizeof(deviceInfoBody), "%s\nID: %04X\n%s %s\n%s",
                     BLE_DEVICE_NAME, (unsigned)store::deviceId(),
                     i18n::tr(store::language(), i18n::S_FIRMWARE), FW_VERSION, "sentinelwallet.io");
            screen = SCREEN_DEVICE_INFO;
            break;
          }
          case 4: doUninstallAllCoins(); break;   // Uninstall All Coins
          case 5: doChangePin();         break;   // Change PIN
          case 6: doResetWallet();       break;   // Reset Device
        }
      }
      break;

    case SCREEN_BATTERY_SAVER:
      if (a.id == BTN_UP)   g_batterySaverSel = (g_batterySaverSel == 0) ? kBatterySaverCount - 1 : g_batterySaverSel - 1;
      if (a.id == BTN_DOWN) g_batterySaverSel = (g_batterySaverSel + 1) % kBatterySaverCount;
      if (a.id == BTN_BACK) screen = SCREEN_SETTINGS;
      if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        store::setAutoLockMinutes(kBatterySaverMinutes[g_batterySaverSel]);
        screen = SCREEN_SETTINGS;
      }
      break;

    case SCREEN_LANGUAGE:
      if (a.id == BTN_UP)   g_languageSel = (g_languageSel == 0) ? kLanguageCount - 1 : g_languageSel - 1;
      if (a.id == BTN_DOWN) g_languageSel = (g_languageSel + 1) % kLanguageCount;
      if (a.id == BTN_BACK) screen = SCREEN_SETTINGS;
      if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        store::setLanguage(g_languageSel);
        display.setLanguage(g_languageSel);
        screen = SCREEN_SETTINGS;
      }
      break;

    case SCREEN_DEVICE_INFO:
      if (a.id == BTN_BACK || (a.id == BTN_SELECT && a.event == EV_PRESS)) {
        screen = SCREEN_SETTINGS;
      }
      break;

    case SCREEN_RECEIVE_QR:
      if (a.id == BTN_BACK || a.id == BTN_SELECT) {
        wallet::endReceive();
        g_recvAddr = ""; g_recvPath = "";
        // Return to account picker if multiple accounts exist, else menu.
        screen = (g_acctCount > 1) ? SCREEN_ACCOUNT_LIST : SCREEN_MENU;
      }
      break;

    case SCREEN_ACCOUNT_LIST: {
      if (a.id == BTN_UP && g_acctListSel > 0) g_acctListSel--;
      else if (a.id == BTN_DOWN && g_acctListSel + 1 < g_acctCount) g_acctListSel++;
      else if (a.id == BTN_BACK) screen = SCREEN_MENU;
      else if (a.id == BTN_SELECT && a.event == EV_PRESS) {
        display.message("QR Code", "Please wait...");
        if (store::coin() == COIN_BTC) {
          if (!wallet::beginReceive(g_entropy, g_entropyLen, g_passphrase)) {
            showDeriveError(g_acctCoins[g_acctListSel], (int)g_acctBipIndex[g_acctListSel]);
            break;
          }
        }
        g_recvCoin  = g_acctCoins[g_acctListSel];
        g_recvIndex = g_acctBipIndex[g_acctListSel];
        updateReceive();
        if (g_recvAddr.length() == 0) { showDeriveError(g_recvCoin, (int)g_recvIndex); break; }
        display.qr(g_recvAddr.c_str());
        screen = SCREEN_RECEIVE_QR;
      }
      break;
    }

    case SCREEN_SIGN_REVIEW: {
      // Confirm page index per coin.
      uint8_t lastPage;
      if (store::coin() == COIN_ADA)                        lastPage = 1;
      else if (store::coin() == COIN_XLM)                   lastPage = xlm::txHasPayment() ? 2 : 1;
      else if (isSolFamily(store::coin()))                  lastPage = sol::txHasTransfer() ? 2 : 1;
      else if (isEvmCoin(store::coin()))                    lastPage = 2;
      else if (store::coin() == COIN_XRP)                   lastPage = 1;
      else if (store::coin() == COIN_ATOM)                  lastPage = 1;
      else if (store::coin() == COIN_DYDX)                  lastPage = 1;
      else if (store::coin() == COIN_AXL)                   lastPage = 1;
      else if (store::coin() == COIN_BABY)                  lastPage = 1;
      else if (store::coin() == COIN_TIA)                   lastPage = 1;
      else if (store::coin() == COIN_TRX)                   lastPage = 1;
      else if (store::coin() == COIN_TON)                   lastPage = 1;
      else if (store::coin() == COIN_DOT)                   lastPage = 1;
      else if (store::coin() == COIN_FIL)                   lastPage = 1;
      else if (store::coin() == COIN_SUI)                   lastPage = 1;
      else if (store::coin() == COIN_APT)                   lastPage = 1;
      else if (store::coin() == COIN_NEAR)                  lastPage = 1;
      else if (store::coin() == COIN_ALGO)                  lastPage = 1;
      else if (store::coin() == COIN_BCH)                   lastPage = 1;
      else if (store::coin() == COIN_USDTTRX)               lastPage = 1;
      else if (store::coin() == COIN_BTTTRX)                lastPage = 1;
      else                                                   lastPage = signer::storedOutputs();

      if (a.id == BTN_UP && g_signPage > 0) g_signPage--;
      else if (a.id == BTN_DOWN && g_signPage < lastPage) g_signPage++;
      else if (a.id == BTN_BACK) {
        if (store::coin() == COIN_ADA)                        ada::clearTx();
        else if (store::coin() == COIN_XLM)                   xlm::clearTx();
        else if (isSolFamily(store::coin()))                  sol::clearTx();
        else if (isEvmCoin(store::coin()))                    eth::clearTx();
        else if (store::coin() == COIN_XRP)                   xrp::clearTx();
        else if (store::coin() == COIN_ATOM)                  cosmos::clearTx();
        else if (store::coin() == COIN_DYDX)                  cosmos::clearTx();
        else if (store::coin() == COIN_AXL)                   cosmos::clearTx();
        else if (store::coin() == COIN_BABY)                  cosmos::clearTx();
        else if (store::coin() == COIN_TIA)                   cosmos::clearTx();
        else if (store::coin() == COIN_TRX)                   tron::clearTx();
        else if (store::coin() == COIN_TON)                   ton::clearTx();
        else if (store::coin() == COIN_DOT)                   dot::clearTx();
        else if (store::coin() == COIN_FIL)                   fil::clearTx();
        else if (store::coin() == COIN_SUI)                   sui::clearTx();
        else if (store::coin() == COIN_APT)                   apt::clearTx();
        else if (store::coin() == COIN_NEAR)                  near::clearTx();
        else if (store::coin() == COIN_ALGO)                  algo::clearTx();
        else if (store::coin() == COIN_BCH)                   bch::clearTx();
        else if (store::coin() == COIN_USDTTRX)                tron::clearTx();
        else if (store::coin() == COIN_BTTTRX)                 tron::clearTx();
        else                                                   signer::clear();
        screen = SCREEN_MENU;
      }
      else if (a.id == BTN_SELECT && a.event == EV_LONGPRESS && g_signPage == lastPage) {
        doSign();
      }
      break;
    }

    case SCREEN_SIGN_DONE:
      if (a.id == BTN_BACK || a.id == BTN_SELECT) screen = SCREEN_MENU;
      break;


    case SCREEN_STUB:
      if (a.id == BTN_BACK || a.id == BTN_SELECT) screen = SCREEN_MENU;
      break;
  }

  render();
}
