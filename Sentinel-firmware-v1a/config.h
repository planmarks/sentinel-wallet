#pragma once
//
// Sentinel — hardware configuration for the Seeed XIAO ESP32-C5
//
// Keep ALL board-specific pin and geometry constants here so the rest of the
// firmware stays hardware-agnostic.

// ---- Firmware identity ------------------------------------------------------
#define FW_NAME    "Sentinel"
#define FW_VERSION "1.0.0"

// ---- Serial -----------------------------------------------------------------
#define SERIAL_BAUD 115200

// ---- OLED (SSD1306, I2C) ----------------------------------------------------
// The XIAO form factor exposes the default I2C bus on SDA=D4, SCL=D5, so
// Wire.begin() needs no arguments. U8g2 uses the 8-bit form of the address.
#define OLED_WIDTH      128
#define OLED_HEIGHT     64
#define OLED_I2C_ADDR7  0x3C            // 7-bit; most 0.96" modules use 0x3C
#define OLED_I2C_ADDR8  (OLED_I2C_ADDR7 << 1)

// ---- Buttons ----------------------------------------------------------------
// Wired between GPIO and GND; internal pull-ups make them active-LOW.
// NOTE: if any of these is a strapping pin on the C5, move it to a free GPIO
// and update the mapping here (see Seeed pin-multiplexing wiki).
#define PIN_BTN_UP      D0
#define PIN_BTN_DOWN    D1
#define PIN_BTN_SELECT  D2   // "OK"
#define PIN_BTN_BACK    D3   // "Back/Del"
#define PIN_BTN_LEFT    D8   // Left  — advances the coin picker (GPIO8, not a strapping pin)
#define PIN_BTN_RIGHT   D9   // Right — steps the coin picker back (GPIO9, not a strapping pin)

// ---- Button timing (ms) -----------------------------------------------------
#define BTN_DEBOUNCE_MS    25
#define BTN_LONGPRESS_MS   700
#define BTN_REPEAT_MS      180   // auto-repeat interval while held (Up/Down)

// ---- Auto-lock --------------------------------------------------------------
// After this long with no button interaction, the device re-locks (wipes keys
// from RAM, turns BLE off) and returns to the PIN screen.
#define AUTO_LOCK_MS       (3UL * 60UL * 1000UL)   // 3 minutes

// ---- PIN & encrypted storage (Phase 3) --------------------------------------
#define PIN_MIN_DIGITS     4
#define PIN_MAX_DIGITS     8
#define PIN_MAX_TRIES      5     // wrong attempts before the wallet self-wipes
#define PBKDF2_ITERS       60000 // KDF cost; tune for the C5 unlock latency
#define NVS_NAMESPACE      "cw"  // NVS namespace for wallet blobs

// ---- BLE (Phase 6, optional, default OFF) -----------------------------------
// Nordic UART Service (NUS) — a de-facto "serial over BLE" profile supported by
// generic BLE terminal apps, so the PSBT flow works over BLE with no custom app.
#define BLE_DEVICE_NAME       "Sentinel Core+"
#define BLE_NUS_SERVICE_UUID  "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_NUS_RX_UUID       "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"  // client -> device (write)
#define BLE_NUS_TX_UUID       "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"  // device -> client (notify)

// Where a signed PSBT should be returned. Defined here (not in the .ino) so the
// type is known before the Arduino IDE's auto-generated function prototypes.
enum SignSource { SRC_SERIAL, SRC_BLE };

// Selected coin (persisted). BTC = native segwit BIP84; ETH = BIP44 m/44'/60';
// SOL = ed25519 SLIP-0010 m/44'/501'; XLM = ed25519 SLIP-0010 m/44'/148';
// ADA = Cardano Icarus/BIP32-Ed25519 m/1852'/1815'.
// NOTE on architecture (2026-07-30): ERC-20/BEP-20 tokens and SPL tokens do
// NOT get their own COIN_* id. A token transfer signs through its native
// chain's existing signer (eth.cpp generically decodes ERC-20 calldata for
// display; sol.cpp generically decodes SPL instructions) — exactly mirroring
// how a real hardware wallet's single "Ethereum app" handles every ERC-20
// token without a dedicated per-token install. Only genuinely distinct
// chains (different curve/address/gas token) get a COIN_* id. This keeps the
// on-device menu to real chains and means new tokens are pure app-side
// CoinMeta additions — no firmware change, ever.
// Every EVM chain other than Ethereum itself (BNB, AVAX, OP, ARB, FTM, ...)
// and every ERC-20 token (USDT, USDC, ...) used to get its own COIN_* id here
// so the on-device menu/label could show its ticker. That was decorative:
// eth.cpp already derives the correct ticker straight from the signed
// payload (chainId for a native transfer, the token's contract address for
// an ERC-20 transfer — see eth::txSignLabel()) independent of which coin is
// selected on-device, and the app's own account-creation flow never
// activated most of these anyway (CoinMeta.deviceSymbol resolves any token
// to 'ETH'). Removing them shrinks the physical home-menu from 54 slots to
// 26 with zero loss of app-side functionality — every one of these chains
// and tokens still shows up, sends, and tracks a balance exactly as before,
// they just all sign through the one "ETH" slot now, the same way Ledger's
// single Ethereum app signs for every EVM chain and token without a
// per-token install. Numbers of the coins that remain are UNCHANGED from
// before this cleanup, specifically so a device's already-stored NVS
// activation bits for real coins stay valid across this update.
//
// Cosmos-family leaves (DYDX/AXL/BABY/TIA) and the TRC-20 ids (USDTTRX,
// BTTTRX) are NOT folded in the same way and keep their own id:
// Cosmos's bech32 HRP is currently a hardcoded literal picked by which coin
// is selected on-device (cosmos::address(..., hrp) in coldwallet.ino) —
// there's no wire field carrying it, unlike EVM's chainId, so collapsing
// these would need a wire-protocol change (app + firmware), not just a
// firmware cleanup. TRON signing is blind-sign (raw bytes, SHA-256'd and
// signed with no field decoding) — firmware has no way to look inside the
// payload to tell "this is a USDT-TRC20/BTT-TRC20 transfer" the way eth.cpp
// decodes ERC-20 calldata, so there's no payload-driven label to derive.
#define COIN_BTC   0
#define COIN_ETH   1   // also every EVM chain + ERC-20 token — see note above
#define COIN_SOL   2
#define COIN_XLM   3
#define COIN_ADA   4
#define COIN_XRP   6   // XRP Ledger — secp256k1 m/44'/144', XRP base58check
#define COIN_ATOM  13  // Cosmos Hub — secp256k1 m/44'/118', bech32 "cosmos", blind-sign
#define COIN_TRX   14  // TRON — secp256k1 m/44'/195', base58check "T...", blind-sign
#define COIN_TON   15  // Gram (Toncoin) — SLIP-10 ed25519 m/44'/607', v4R2 address, blind-sign
#define COIN_DOT      16  // Polkadot — SLIP-10 ed25519 m/44'/354', SS58 address (network 0), blind-sign
#define COIN_USDTTRX  17  // Tether TRC-20 — same address as TRX, blind-sign, no payload-driven label possible
// 18 was COIN_USDCTRX (USD Coin TRC-20) — removed 2026-08-01, Circle is
// discontinuing USDC on Tron; left as a permanent gap (never reused, same
// as every other removed id) so old NVS activation bits on a device already
// in the field can't collide with a different coin.
#define COIN_LTC   24  // Litecoin — P2WPKH BIP84 m/84'/2'/0', bech32 "ltc"
#define COIN_DOGE  25  // Dogecoin — P2PKH  BIP44 m/44'/3'/0', p2pkh 0x1E
#define COIN_DASH   39  // Dash — P2PKH  BIP44 m/44'/5'/0',  p2pkh 0x4C
#define COIN_DGB    40  // DigiByte — P2WPKH BIP84 m/84'/20'/0', bech32 "dgb"
#define COIN_RVN    41  // Ravencoin — P2PKH  BIP44 m/44'/175'/0', p2pkh 0x3C
#define COIN_SUI    42  // Sui — SLIP-10 ed25519 m/44'/784'/0'/0'/0', blind-sign
#define COIN_APT    43  // Aptos — SLIP-10 ed25519 m/44'/637'/0'/0'/0', blind-sign
#define COIN_NEAR   44  // NEAR — SLIP-10 ed25519 m/44'/397'/0'/0'/0', blind-sign
#define COIN_ALGO   45  // Algorand — SLIP-10 ed25519 m/44'/283'/0'/0'/0', blind-sign
#define COIN_DYDX   46  // dYdX — Cosmos-SDK secp256k1 m/44'/118'/0'/0/i, bech32 "dydx"
#define COIN_AXL    47  // Axelar — Cosmos-SDK secp256k1 m/44'/118'/0'/0/i, bech32 "axelar"
#define COIN_BABY   48  // Babylon — Cosmos-SDK secp256k1 m/44'/118'/0'/0/i, bech32 "bbn"
#define COIN_BCH    49  // Bitcoin Cash — P2PKH m/44'/145'/0'/0/i, CashAddr, SIGHASH_FORKID
#define COIN_TIA    53  // Celestia — Cosmos-SDK secp256k1 m/44'/118'/0'/0/i, bech32 "celestia"
#define COIN_FIL    54  // Filecoin (native) — secp256k1 m/44'/461'/0'/0/i, "f1..." address, blind-sign.
                        // Distinct from FEVM ("FILEVM" app-side), which shares ETH's key/address and
                        // signs through COIN_ETH like every other EVM chain — see eth.cpp/coinFromSymbol().
#define COIN_BTTTRX   55  // BitTorrent TRC-20 — same address as TRX, blind-sign, mirrors COIN_USDTTRX
                          // exactly (own dedicated id for the same reason: Tron signing has no payload
                          // to derive a per-token label from). Distinct from BTT (native BTTC chain,
                          // EVM-compatible, signs through COIN_ETH) and BTTETH/BTTBSC (wrapped-token
                          // siblings, also COIN_ETH) — this is BTT's real, separate Tron deployment.
#define COIN_COUNT    56
