#include "ble.h"
#include "config.h"
#include "store.h"

#include <NimBLEDevice.h>   // NimBLE-Arduino 2.x
#include <vector>

namespace {
bool                  s_initialized = false;  // NimBLE stack brought up (once)
bool                  s_enabled   = false;    // user intent: advertising/connectable
volatile bool         s_connected     = false;
volatile bool         s_justConnected = false;
NimBLEServer         *s_server    = nullptr;
NimBLECharacteristic *s_tx        = nullptr;

// Per-device identity — a random 16-bit id (store::deviceId(), generated
// once ever via the chip's HWRNG, NOT the radio MAC). Advertised so the app
// can recognise a Sentinel and tell multiple devices apart.
//
// Deliberately NOT the factory eFuse MAC, despite that being the original
// design (and what this comment used to say) — two real problems with that:
// (1) it never actually agreed with SENTINEL_READY's own reported id in
// practice (a real, observed live discrepancy — both were *supposed* to
// derive from the same ESP.getEfuseMac() call, but didn't in practice,
// most likely because the physical unit's firmware predates the exact
// derivation this file now has and was never re-flashed to match); (2)
// broadcasting a stable factory MAC in cleartext, forever, in every scan
// response is a genuine BLE privacy anti-pattern — anyone with a BLE
// scanner in range can passively track one specific physical device
// indefinitely, which is exactly the problem Bluetooth's own Resolvable
// Private Address mechanism exists to prevent. A random, non-MAC-derived
// id sidesteps both: one single stored value, read by both this file and
// notifyReady() (coldwallet.ino), so there is exactly one source of truth
// left to ever disagree with itself, and it reveals nothing about the
// chip's real hardware address.
char    s_advName[20] = {0};   // "Sentinel Core+"
uint8_t s_devId[2]    = {0};   // store::deviceId(), little-endian
bool    s_idReady     = false;

// Handoff between the BLE host task and the main loop. The C5 is single-core
// so tasks interleave cooperatively — no critical section needed for the
// vector itself.
//
// This used to be a single-slot handoff (one String + a ready flag), which
// silently dropped or corrupted commands whenever the app sent several
// lines faster than the main loop could drain them via takePsbt() — a real,
// confirmed bug: draining several queued ACCT_DELETE/ACCT_RENAME ops on
// reconnect (each triggering a real, non-instant NVS flash write) sent them
// back-to-back with no delay, and any line completing while the previous
// one was still unconsumed just vanished (its bytes were never even
// cleared from s_rxBuf, so the *next* line's characters got silently
// appended onto them instead, corrupting that one too). A real FIFO queue
// means multiple rapid commands are all correctly preserved and processed
// in order, regardless of how fast the app sends them.
String              s_rxBuf;
std::vector<String> s_lineQueue;

class ServerCB : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer *, NimBLEConnInfo &) override { s_connected = true; s_justConnected = true; }
  void onDisconnect(NimBLEServer *, NimBLEConnInfo &, int) override {
    s_connected = false;
    // Only re-advertise if BLE is still enabled. When BLE is turned off (toggle
    // or auto-lock) we deliberately disconnect the client and must NOT re-advertise.
    if (s_enabled) NimBLEDevice::startAdvertising();
  }
};

class RxCB : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic *c, NimBLEConnInfo &) override {
    NimBLEAttValue v = c->getValue();
    for (size_t i = 0; i < v.length(); i++) {
      char ch = (char)v[i];
      if (ch == '\n' || ch == '\r') {
        if (s_rxBuf.length() > 0) {
          // Queue it rather than requiring the previous line to already be
          // consumed — see the comment on s_lineQueue above for the bug
          // this replaces. Bounded so a truly stuck main loop can't grow
          // this unbounded; 32 queued lines is far more than any real
          // command burst this device handles.
          if (s_lineQueue.size() < 32) s_lineQueue.push_back(s_rxBuf);
          s_rxBuf = "";
        }
      } else if (s_rxBuf.length() < 16384) {
        s_rxBuf += ch;
      }
    }
  }
};

ServerCB s_serverCb;
RxCB     s_rxCb;

// Capture the stable random device id for the scan-response manufacturer
// data (computed once) — see the s_devId doc comment above for why this is
// store::deviceId() and not the eFuse MAC.
void computeIdentity() {
  if (s_idReady) return;
  uint16_t id = store::deviceId();
  s_devId[0] = (uint8_t)(id & 0xFF);
  s_devId[1] = (uint8_t)((id >> 8) & 0xFF);
  snprintf(s_advName, sizeof(s_advName), "%s", BLE_DEVICE_NAME);
  s_idReady = true;
}
}  // namespace

namespace ble {

void begin() { computeIdentity(); }   // build the device identity (no radio yet)

bool isEnabled()   { return s_enabled; }
bool isConnected() { return s_connected; }
bool justConnected() { if (!s_justConnected) return false; s_justConnected = false; return true; }
const char *advName() { computeIdentity(); return s_advName; }

void enable(const char *name) {
  if (s_enabled) return;

  // Bring the NimBLE stack up exactly ONCE per boot. Repeated init()/deinit()
  // cycles are a known crash source in NimBLE-Arduino — and deinit() is what was
  // rebooting the device when BLE was turned off. After the first enable the
  // stack stays up and enable/disable only start/stop advertising.
  (void)name;   // the advertised name is derived from the MAC (computeIdentity)
  if (!s_initialized) {
    computeIdentity();
    NimBLEDevice::init(s_advName);              // GAP name = "Sentinel-XXXX"
    NimBLEDevice::setMTU(247);

    s_server = NimBLEDevice::createServer();
    s_server->setCallbacks(&s_serverCb);

    NimBLEService *svc = s_server->createService(BLE_NUS_SERVICE_UUID);
    s_tx = svc->createCharacteristic(BLE_NUS_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
    NimBLECharacteristic *rx = svc->createCharacteristic(
        BLE_NUS_RX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
    rx->setCallbacks(&s_rxCb);
    svc->start();

    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    // Primary advertisement: the per-device name "Sentinel-XXXX" (fits the
    // 31-byte budget with the flags; the 128-bit NUS UUID is intentionally left
    // out and discovered over GATT after connecting).
    adv->setName(s_advName);

    // Scan response: manufacturer-specific data so an app can (a) recognise a
    // genuine Sentinel via the "SNTL" magic and (b) tell devices apart via
    // the random 16-bit device id. Layout: FFFF | 'S''N''T''L' | id[2] |
    // fmt(0x02). Format bumped 0x01->0x02 since the id field itself shrank
    // (was 6 raw MAC bytes, now a 2-byte random id) — lets the app tell a
    // (very unlikely to still exist in the wild) old-format device apart
    // from this one rather than silently misparsing it.
    uint8_t mfg[9];
    mfg[0] = 0xFF; mfg[1] = 0xFF;               // company id 0xFFFF (internal / no company)
    mfg[2] = 'S'; mfg[3] = 'N'; mfg[4] = 'T'; mfg[5] = 'L';
    memcpy(mfg + 6, s_devId, 2);
    mfg[8] = 0x02;                              // identity data format version
    NimBLEAdvertisementData scanData;
    scanData.setManufacturerData(mfg, sizeof(mfg));
    adv->setScanResponseData(scanData);
    adv->enableScanResponse(true);

    s_initialized = true;
  }

  s_enabled = true;              // set before advertising so callbacks observe it
  NimBLEDevice::getAdvertising()->start();
}

void disable() {
  if (!s_enabled) return;

  // Turn BLE "off" WITHOUT tearing down the stack (see enable()): stop
  // advertising and drop any connected client. The controller stays initialized
  // but is no longer discoverable or connectable. This is stable across repeated
  // toggles, unlike NimBLEDevice::deinit(), which was crashing/rebooting the C5.
  s_enabled = false;             // clear first so onDisconnect won't re-advertise
  NimBLEDevice::getAdvertising()->stop();
  if (s_server) {
    std::vector<uint16_t> peers = s_server->getPeerDevices();
    for (uint16_t h : peers) s_server->disconnect(h);
  }
  s_connected = false;
  s_rxBuf = "";
  s_lineQueue.clear();
}

bool takePsbt(String &out) {
  if (s_lineQueue.empty()) return false;
  out = s_lineQueue.front();
  s_lineQueue.erase(s_lineQueue.begin());
  return true;
}

void sendLine(const String &s) {
  if (!s_enabled || !s_tx || !s_connected) return;
  const size_t CHUNK = 20;   // safe for the default BLE MTU
  for (size_t i = 0; i < s.length(); i += CHUNK) {
    String part = s.substring(i, min(i + CHUNK, s.length()));
    s_tx->setValue((const uint8_t *)part.c_str(), part.length());
    s_tx->notify();
    delay(20);
  }
  s_tx->setValue((const uint8_t *)"\n", 1);   // line terminator
  s_tx->notify();
}

}  // namespace ble
