#include "fil.h"
#include "wallet.h"
#include "blake2.h"

#include <Bitcoin.h>
#include <string.h>

namespace {

static const char HEXCH[]  = "0123456789abcdef";
static const char B32CH[]  = "abcdefghijklmnopqrstuvwxyz234567";  // RFC4648 lowercase

static const size_t MAX_PAYLOAD = 256;  // CBOR-encoded Message for a plain transfer is ~65-100 bytes

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

// RFC4648 base32, lowercase, no padding.
String base32EncodeLower(const uint8_t *data, size_t len) {
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

// Derives the secp256k1 keypair at m/44'/461'/0'/0/index and returns the
// uncompressed 65-byte SEC1 public key (0x04 || X(32) || Y(32)).
bool derivePub(const uint8_t *entropy, size_t entLen, const char *passphrase,
               uint32_t index, HDPrivateKey &child, uint8_t pubSec[65]) {
  String m = wallet::entropyToSeedPhrase(entropy, entLen);
  if (m.length() == 0) return false;
  HDPrivateKey root(m, String(passphrase ? passphrase : ""), &Mainnet);
  m = "";
  char path[40];
  snprintf(path, sizeof(path), "m/44h/461h/0h/0/%lu", (unsigned long)index);
  child = root.derive(path);
  PublicKey pub = child.publicKey();
  pub.compressed = false;
  if (pub.sec(pubSec, 65) != 65) return false;
  return true;
}

}  // namespace

namespace fil {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  HDPrivateKey child;
  uint8_t pubSec[65];
  if (!derivePub(entropy, entLen, passphrase, index, child, pubSec)) return String("");

  // payload = Blake2b-160(uncompressed pubkey)
  uint8_t payload[20];
  blake2b(payload, sizeof(payload), pubSec, sizeof(pubSec), nullptr, 0);

  // checksum = Blake2b-32bit(protocolByte(0x01) || payload)
  uint8_t protoAndPayload[21];
  protoAndPayload[0] = 0x01;
  memcpy(protoAndPayload + 1, payload, 20);
  uint8_t checksum[4];
  blake2b(checksum, sizeof(checksum), protoAndPayload, sizeof(protoAndPayload), nullptr, 0);

  uint8_t toEncode[24];
  memcpy(toEncode, payload, 20);
  memcpy(toEncode + 20, checksum, 4);

  return String("f1") + base32EncodeLower(toEncode, sizeof(toEncode));
}

bool loadTx(const String &line) {
  clearTx();
  // FIL|acct|messageCborHex
  String parts[3]; int np = 0, start = 0;
  for (int i = 0; i <= (int)line.length() && np < 3; i++) {
    if (i == (int)line.length() || line[i] == '|') {
      parts[np++] = line.substring(start, i); start = i + 1;
    }
  }
  if (np < 3 || parts[0] != "FIL") return false;
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
  HDPrivateKey child;
  uint8_t pubSec[65];
  if (!derivePub(entropy, entLen, passphrase, s_acct, child, pubSec)) return String("");

  // Filecoin signing digest: the message hash is wrapped in a CID before the
  // final hash, not signed directly. CID_PREFIX is a fixed 6-byte constant
  // (CIDv1 + dag-cbor codec + blake2b-256 multihash code+length varints) —
  // see fil.h's header comment for how this was independently verified.
  static const uint8_t CID_PREFIX[6] = { 0x01, 0x71, 0xA0, 0xE4, 0x02, 0x20 };
  uint8_t messageHash[32];
  blake2b(messageHash, sizeof(messageHash), s_payload, s_payloadLen, nullptr, 0);

  uint8_t cidInput[6 + 32];
  memcpy(cidInput, CID_PREFIX, 6);
  memcpy(cidInput + 6, messageHash, 32);

  uint8_t digest[32];
  blake2b(digest, sizeof(digest), cidInput, sizeof(cidInput), nullptr, 0);

  Signature sig = child.sign(digest);

  uint8_t sigBytes[65];
  sig.bin(sigBytes, sizeof(sigBytes));  // <r[32]><s[32]><recoveryId>

  String out; out.reserve(130);
  for (int i = 0; i < 65; i++) { out += HEXCH[sigBytes[i] >> 4]; out += HEXCH[sigBytes[i] & 0x0F]; }
  return out;
}

void clearTx() {
  s_loaded     = false;
  s_acct       = 0;
  s_payloadLen = 0;
  memset(s_payload, 0, sizeof(s_payload));
}

}  // namespace fil
