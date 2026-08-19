#pragma once
//
// BNB Smart Chain support.
//   Address: BIP44 m/44'/60'/0'/0/i — identical derivation to Ethereum.
//            BSC is EVM-compatible; the same secp256k1 key pair and 0x…
//            address format is used by Ledger, MetaMask and Trust Wallet.
//   Signing: EIP-1559 RLP, same as ETH — the chain is distinguished by
//            chainId (BSC mainnet = 56, testnet = 97) embedded in the tx.
//            The app sends transactions with "BNB|…" prefix; eth::loadTx()
//            accepts both "ETH" and "BNB" prefixes and signs identically.
//
#include <Arduino.h>

namespace bnb {

// EIP-55 checksummed "0x…" address — same derivation as eth::address().
String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index);

}  // namespace bnb
