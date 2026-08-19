<div align="center">

# 🛡️ Sentinel Hardware Wallet

### Your keys and coins kept offline, signed offline, on a device you hold in your hand.

![Version](https://img.shields.io/badge/firmware-V0.9B-2b6cb0)
![Platform](https://img.shields.io/badge/platform-ESP32--C5-4a5568)
![Chains](https://img.shields.io/badge/networks-14-dd6b20)
![Interface](https://img.shields.io/badge/interface-USB%20%2B%20optional%20BLE-805ad5)
![Open Source](https://img.shields.io/badge/firmware-open%20source-38a169)

*A pocket-sized, open-source cold wallet for 14 blockchains.*

</div>

---

> ⚠️ **Status:** Firmware version `1.0.0`. This is a hobbyist / educational hardware-wallet project,
> not a certified secure product. Please read the [Security Model & Honest Limitations](#-security-model--honest-limitations)
> section before storing meaningful funds.

---

## 📖 What It Is

A cold wallet keeps the secret keys that control your crypto **offline**, away from any
internet-connected computer. Sentinel follows that model:

- **Keys are born on the device.** A BIP39 recovery phrase (12/18/24 words) is generated from the
  chip's hardware random number generator — or you can restore an existing phrase.
- **Keys stay on the device.** The seed is encrypted and written to the chip's flash. It only ever
  exists in plaintext in RAM while the wallet is unlocked, and it's wiped from RAM the moment you lock.
- **The device only signs what you approve.** The companion app builds a transaction and sends it
  over. Sentinel shows you the recipients and the fee on its own screen, and it won't sign until you
  press and hold the confirm button.
- **It works air-gapped.** USB and Bluetooth are just transports for passing transaction data back
  and forth; the signing itself is fully offline, and Bluetooth is **off by default**.

**Hardware target:** Seeed XIAO ESP32-C5 · Arduino-ESP32 core 3.3.5+
**Display:** SSD1306/SSD1315 128×64 I²C OLED
**Interface:** 6 buttons (Up / Down / OK / Back / Left / Right), USB serial, optional BLE

---

## 🪙 Supported Cryptocurrencies

Sentinel supports a wide range of chains across multiple cryptographic families. Like a real
hardware wallet, **EVM chains and tokens all sign through a single "Ethereum" engine**, and SPL /
TRC-20 tokens sign through their parent chain — so the list of *assets* you can hold is much larger
than the list of on-device menu entries.

### Bitcoin & UTXO chains

| Coin | Ticker | Curve | Derivation | Address type |
|------|--------|-------|------------|--------------|
| Bitcoin | BTC | secp256k1 | BIP84 `m/84'/0'` | Native SegWit (bech32) |
| Litecoin | LTC | secp256k1 | BIP84 `m/84'/2'` | Native SegWit (`ltc…`) |
| Dogecoin | DOGE | secp256k1 | BIP44 `m/44'/3'` | P2PKH |
| Dash | DASH | secp256k1 | BIP44 `m/44'/5'` | P2PKH |
| DigiByte | DGB | secp256k1 | BIP84 `m/84'/20'` | Native SegWit (`dgb…`) |
| Ravencoin | RVN | secp256k1 | BIP44 `m/44'/175'` | P2PKH |
| Bitcoin Cash | BCH | secp256k1 | `m/44'/145'` | CashAddr (SIGHASH_FORKID) |

Bitcoin (and other PSBT chains) support full **PSBT** signing with itemized output review.

### Ethereum & EVM chains

The **Ethereum** engine (`secp256k1`, BIP44 `m/44'/60'`, EIP-1559) signs for Ethereum **and every
EVM-compatible chain and ERC-20 token** the companion app knows about. The correct label is derived
from the transaction payload itself (chain ID for native transfers, contract address for tokens).

- **Ethereum (ETH)** and ERC-20 tokens such as **USDT** and **USDC**
- EVM chains routed through the same engine include:
  **BNB** Smart Chain, **Avalanche** (AVAX), **Polygon** (POL), **Base**, **Optimism** (OP),
  **Arbitrum** (ARB), **Cronos** (CRO), **Fantom** (FTM), **Ethereum Classic** (ETC), **Linea**,
  **Celo**, **Mantle** (MNT), **Flare** (FLR), **XDC**, **KuCoin Chain** (KCS), **X Layer** (OKB),
  **Filecoin EVM** (FILEVM), **BitTorrent Chain** (BTT), **IOTA EVM**, **Sonic** (S),
  **Kaia** (KAIA), **Hyperliquid** (HYPE), **Monad** (MON), and others (XTZ, XPL, M).

> New EVM chains and ERC-20 tokens generally need **no firmware change** — they're added on the app
> side, since they all share Ethereum's keys, addresses, and signing.

### Solana & SPL tokens

| Coin | Ticker | Curve | Derivation |
|------|--------|-------|------------|
| Solana | SOL | ed25519 | SLIP-0010 `m/44'/501'` |

Solana transfers are decoded and itemized for review; **SPL tokens** sign through the same Solana
engine.

### Cosmos ecosystem

All Cosmos-SDK chains use `secp256k1`, `m/44'/118'`, and bech32 addresses (differing only by prefix):

| Coin | Ticker | Address prefix |
|------|--------|----------------|
| Cosmos Hub | ATOM | `cosmos…` |
| dYdX | DYDX | `dydx…` |
| Axelar | AXL | `axelar…` |
| Babylon | BABY | `bbn…` |
| Celestia | TIA | `celestia…` |

### Other Layer-1 networks

| Coin | Ticker | Curve | Derivation | Notes |
|------|--------|-------|------------|-------|
| XRP Ledger | XRP | secp256k1 | `m/44'/144'` | base58check |
| Stellar | XLM | ed25519 | SLIP-0010 `m/44'/148'` | payments itemized |
| Cardano | ADA | BIP32-Ed25519 (Icarus) | `m/1852'/1815'` | Blake2b, staking support |
| Tron | TRX | secp256k1 | `m/44'/195'` | base58check (`T…`) |
| Tether on Tron | USDT (TRC-20) | secp256k1 | shares TRX address | |
| BitTorrent on Tron | BTT (TRC-20) | secp256k1 | shares TRX address | |
| Toncoin / Gram | TON | ed25519 | SLIP-10 `m/44'/607'` | v4R2 address |
| Polkadot | DOT | ed25519 | SLIP-10 `m/44'/354'` | SS58 address |
| Sui | SUI | ed25519 | SLIP-10 `m/44'/784'` | |
| Aptos | APT | ed25519 | SLIP-10 `m/44'/637'` | |
| NEAR Protocol | NEAR | ed25519 | SLIP-10 `m/44'/397'` | |
| Algorand | ALGO | ed25519 | SLIP-10 `m/44'/283'` | |
| Filecoin (native) | FIL | secp256k1 | `m/44'/461'` | `f1…` address |

> **Mainnet only.** This firmware deliberately does not support testnets.

---

## 🔒 Security Measures

Sentinel implements defense in depth across storage, key handling, transaction approval, and
connectivity.

### PIN & encrypted storage

- **PIN-gated unlock.** The device is locked at boot and requires a **4–8 digit PIN** to unlock.
- **Strong encryption at rest.** The seed (and optional passphrase) are stored with
  **AES-256-GCM** (authenticated encryption). The key is derived from your PIN using
  **PBKDF2-HMAC-SHA256 with 60,000 iterations** and a **random 16-byte salt** unique to each wallet.
  Each record also uses a random 12-byte IV, a 16-byte authentication tag, and associated data (AAD)
  binding — so tampered or corrupted ciphertext is rejected rather than mis-decrypted.
- **Anti-brute-force self-wipe.** After **5 wrong PIN attempts** the wallet **erases itself**.
  Crucially, the attempt counter is incremented **and persisted to flash *before* the PIN is
  checked**, so pulling power mid-attempt still "burns" the try — defeating power-cycle brute-force
  attacks.

### Key handling

- **Keys live in RAM only.** The decrypted seed exists in plaintext only while unlocked. On lock,
  auto-lock, or reset, all key material is **zeroized** (`mbedtls_platform_zeroize`), including
  temporary buffers, PIN buffers, and mnemonic strings after use.
- **Hardware RNG.** New seeds and cryptographic salts/IVs come from the ESP32-C5's hardware random
  number generator.
- **Optional BIP39 passphrase (25th word).** Adds a second secret on top of the seed, stored
  encrypted alongside it — enabling hidden-wallet style protection.
- **The recovery phrase is shown only on the OLED** — never printed to Serial or sent over BLE.
- **Auto-lock on inactivity.** After a configurable "Battery Saver" timeout, the device wipes keys
  from RAM, turns Bluetooth off, and returns to the PIN screen.

### Transaction safety

- **Offline signing.** Private keys never leave the device; the companion app never sees them. Only
  the *signed* transaction/PSBT is returned.
- **On-device review + hold-to-confirm.** Recipients and fees are shown on the device's own screen,
  and nothing is signed until you **press and hold** the confirm button. A compromised computer or
  app cannot make the device sign silently.
- **Blind-signing is off by default.** For chains whose transactions can't be fully decoded and
  itemized on-device, Sentinel **refuses to sign** unless you have explicitly enabled "Blind sign"
  for that specific coin in its settings — mirroring the blind-signing guard used by mainstream
  hardware wallets.

### Connectivity & privacy

- **Bluetooth is optional and off by default.** BLE is only a *transport* (a Nordic UART "serial
  over BLE" profile). The radio only comes up **after** the wallet is unlocked, a transaction sent
  over BLE **still** requires on-device confirmation, and BLE is torn down on lock.
- **No MAC-address tracking.** The device advertises a **random 16-bit ID** (generated once from the
  hardware RNG) instead of its factory Bluetooth MAC, so a passive scanner can't persistently track a
  specific physical unit.
- **Shoulder-surfing-resistant PIN pad.** The on-screen digit cursor starts on a **random** digit and
  jumps to a **new random** digit after each entry, so an onlooker can't infer digits by counting
  cursor movements. The PIN screen also dims when idle.

### Auditable, self-contained cryptography

All cryptographic primitives are vendored and run locally with **no network calls**:

- **TweetNaCl** — ed25519 signatures (Solana, Stellar, TON, DOT, Sui, Aptos, NEAR, Algorand)
- **SLIP-0010** — ed25519 hierarchical key derivation
- **BLAKE2b** — Cardano key derivation / hashing
- **uBitcoin** — secp256k1 keys, addresses, and PSBT signing
- **mbedTLS** — AES-256-GCM and PBKDF2 for storage encryption
- **qrcodegen** — offline QR code generation for receive addresses

---

## 🧭 How You Use It

1. **First boot:** create a **New Device** (generate a fresh recovery phrase) or **Restore** an
   existing 12/18/24-word phrase. Optionally add a passphrase. Set a PIN.
2. **Write down your recovery phrase** (shown only on the device screen) and store it safely offline.
3. **Receive:** pick a coin, view your address as text and a scannable **QR code**.
4. **Send:** the companion app builds a transaction and sends it over USB or BLE. Review the outputs
   and fee on the device, then **hold OK** to sign. The signed transaction goes back to the app to
   broadcast.
5. **Settings:** toggle Bluetooth, set the auto-lock timeout, change language, change PIN, per-coin
   blind-sign, uninstall coins, or reset the device.

---

## ⚖️ Security Model & Honest Limitations

To use this project responsibly, understand what it does **and doesn't** protect against:

- **No dedicated secure element.** The ESP32-C5 is a general-purpose microcontroller. Your keys are
  protected by **PIN-derived encryption + the 5-try self-wipe**, not by tamper-resistant secure-chip
  hardware. The strength of your protection therefore depends heavily on your **PIN choice** (and, for
  extra safety, a **passphrase**). A determined attacker with physical possession, lab equipment, and
  unlimited time is outside this design's threat model.
- **Blind signing carries risk.** Enabling blind-sign for a chain means you're trusting the
  transaction the app hands you, because the device can't fully decode it. Enable it only when you
  need it, and understand what you're approving.
- **You are your own backup.** There is no "forgot PIN" recovery. If you forget your PIN (self-wipe)
  or lose your device, **only your written recovery phrase can restore your funds.** Protect that
  phrase like the keys it is.
- **Hobbyist firmware.** This code has not undergone a formal third-party security audit. Review the
  source, and consider it experimental.

---

## 📂 Project Layout

- `coldwallet.ino` — main firmware: UI, menus, flows, command handling
- `config.h` — hardware pins, coin IDs, and derivation notes
- `store.cpp/.h` — encrypted NVS storage, PIN, self-wipe, settings
- `signer.cpp/.h` — PSBT loading, output review, signing
- `wallet.cpp/.h` — seed/entropy, BIP39, address derivation helpers
- `ble.cpp/.h` — optional Bluetooth (Nordic UART) transport
- Per-chain modules — `eth`, `sol`, `xlm`, `ada`, `xrp`, `cosmos`, `tron`, `ton`, `dot`, `sui`,
  `apt`, `near`, `algo`, `bch`, `fil`, `bnb`, etc.
- Vendored crypto — `tweetnacl`, `ed25519`, `slip10`, `blake2*`, `qrcodegen`

---

*Sentinel is provided as-is, for educational and personal use. Always verify addresses and
transaction details on the device screen before confirming.*

