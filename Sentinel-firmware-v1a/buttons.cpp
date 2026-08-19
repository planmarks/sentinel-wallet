#include "buttons.h"
#include "config.h"

void Buttons::begin() {
  const uint8_t pins[BTN_COUNT] = {
    PIN_BTN_UP, PIN_BTN_DOWN, PIN_BTN_SELECT, PIN_BTN_BACK, PIN_BTN_LEFT, PIN_BTN_RIGHT
  };
  for (uint8_t i = 0; i < BTN_COUNT; i++) {
    st_[i].pin          = pins[i];
    st_[i].stableDown   = false;
    st_[i].lastRaw      = false;
    st_[i].lastChangeMs = 0;
    st_[i].downSinceMs  = 0;
    st_[i].longFired    = false;
    st_[i].nextRepeatMs = 0;
    pinMode(pins[i], INPUT_PULLUP);
  }
}

bool Buttons::poll(ButtonAction &out) {
  const uint32_t now = millis();

  for (uint8_t i = 0; i < BTN_COUNT; i++) {
    State &s = st_[i];

    // --- debounce ---
    const bool raw = (digitalRead(s.pin) == LOW);  // active-LOW
    if (raw != s.lastRaw) {
      s.lastRaw = raw;
      s.lastChangeMs = now;
    }

    const bool settled = (now - s.lastChangeMs) >= BTN_DEBOUNCE_MS;
    const bool isNav    = (i == BTN_UP || i == BTN_DOWN || i == BTN_LEFT || i == BTN_RIGHT);

    if (settled && raw != s.stableDown) {
      // debounced edge
      s.stableDown = raw;
      if (raw) {
        // press-down edge
        s.downSinceMs  = now;
        s.longFired    = false;
        s.nextRepeatMs = now + BTN_LONGPRESS_MS;  // repeat starts after this
        if (isNav) {
          out = { (ButtonId)i, EV_PRESS };        // nav: act immediately
          return true;
        }
      } else {
        // release edge: SELECT/BACK report the short press here (if not long)
        if (!isNav && !s.longFired) {
          out = { (ButtonId)i, EV_PRESS };
          return true;
        }
      }
      continue;
    }

    // --- held behaviour ---
    if (s.stableDown) {
      if (isNav) {
        if (now >= s.nextRepeatMs) {
          s.nextRepeatMs = now + BTN_REPEAT_MS;
          out = { (ButtonId)i, EV_PRESS };
          return true;
        }
      } else {
        if (!s.longFired && (now - s.downSinceMs) >= BTN_LONGPRESS_MS) {
          s.longFired = true;
          out = { (ButtonId)i, EV_LONGPRESS };
          return true;
        }
      }
    }
  }

  return false;
}
