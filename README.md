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

Sentinel keeps your private keys **off the internet, off your phone, and off your
computer**. Your recovery phrase is created *on the device* from a hardware random
generator, sealed behind a PIN, and **never leaves the box**. To spend, a companion
app builds the transaction, Sentinel shows you exactly what you're signing on its
screen, you approve it with a physical button and only a **signature** comes back.

## ✨ Why Sentinel

- 🔑 **On-device key generation:** 24-word recovery phrase from a true hardware
  random source, shown only on Sentinel's own screen.
- 🔒 **PIN-protected & encrypted:** Your seed is sealed with AES-256-GCM behind a
  PIN that is *never stored* on the device.
- 💣 **Anti-theft self-wipe:** Too many wrong PIN attempts and the wallet erases
  itself. The counter survives power-cycling, so it can't be cheated.
- 🧩 **Optional passphrase:** Add a "25th word" for an extra hidden layer.
- 👁️ **You sign what you see:** Every transaction's recipient, amount, and fee
  are shown on-screen and require a physical **hold-to-confirm**.
- 📷 **QR receive addresses:** Ccan straight into any sending app.
- 📶 **Offline by default:** Works over USB; Bluetooth is optional and **off by
  default**, and is never the security boundary.
- 🆔 **Know your device:** Each unit has a unique identity so you can tell multiple
  Sentinels apart in the companion app.
- 🔋 **Smart power saving:** Dims and locks itself after inactivity, waking on a
  button press.
- 🛠️ **Fully open:** Readable firmware and permissive libraries. Audit it, build
  on it, extend it.

## 🪙 Supported networks

| | Networks |
|---|---|
| **Bitcoin** | BTC (native SegWit) |
| **Ethereum & EVM** | Ethereum, BNB Chain, Avalanche, Base, Polygon, Cronos — plus **ERC-20 tokens (USDT, USDC)** |
| **Others** | XRP · Solana · Stellar · Cardano · Cosmos (ATOM) · TRON · TON |

**14 networks** from one device, with more possible thanks to the open firmware.

## 🔐 Security at a glance

- Keys are **generated and stored only on the device**; the seed is shown only on
  the OLED, never over USB or Bluetooth.
- Seed encrypted **at rest** (AES-256-GCM) with a **PIN-derived** key.
- **5-strike self-wipe** that survives power loss.
- **Every signature needs a physical confirmation** after on-device review.
- Signatures use **deterministic (RFC6979) nonces**, no random-number leakage.

## 🔧 Hardware

| Part | Details |
|------|---------|
| **MCU** | Seeed Studio XIAO ESP32-C5: RISC-V, 8 MB flash + 8 MB PSRAM, hardware crypto accelerators, Secure Boot v2 & flash-encryption capable |
| **Display** | 0.96" OLED (128×64): shows your seed backup, addresses/QRs, and what you're signing |
| **Controls** | 6 tactile buttons: Up / Down / OK / Back · Left / Right |
| **Connectivity** | USB-C · optional Bluetooth LE (off by default) |

Compact, low-power, and built from widely available parts.

## ⛽ Behind the Sentinel Wallet

### Aleks Sakson
- Co-founder of KIISU Development Board
- Co-Founder of Taskendo project management platform
- Co-Founder of Planmarks Marketing & Design Agency

### Tristan Zenin
- Co-Founder of Planmarks Marketing & Design Agency
- Co-Founder of Taskendo project management platform
