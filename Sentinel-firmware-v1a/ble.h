#pragma once
//
// Optional BLE transport for PSBTs, using the Nordic UART Service (NUS) — a
// "serial over BLE" profile that generic BLE terminal apps understand.
//
// SECURITY: BLE is only a transport. A PSBT received over BLE still goes through
// the same on-device review + hold-to-confirm before signing, and the radio is
// only brought up after the wallet is unlocked. BLE is never the trust boundary.

#include <Arduino.h>

namespace ble {

void begin();                       // one-time init of module state (no radio)
void enable(const char *name);      // bring up the radio + advertise
void disable();                     // tear down the radio
bool isEnabled();
bool isConnected();
bool justConnected();   // returns true once per new client connection (consume-on-read)

// The device's advertised name, e.g. "Sentinel-A1B2" (derived from the factory
// MAC). Stable per device; lets the user/app tell multiple units apart.
const char *advName();

// If a complete line (newline-terminated) has arrived, move it into `out` and
// return true. Safe to call from the main loop.
bool takePsbt(String &out);

// Send a line to the connected client (chunked to fit the BLE MTU).
void sendLine(const String &s);

}  // namespace ble
