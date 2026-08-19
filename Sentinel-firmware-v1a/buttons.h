#pragma once
//
// Debounced button input with long-press and auto-repeat.
// Hardware-agnostic apart from the pin list pulled from config.h.

#include <Arduino.h>

enum ButtonId {
  BTN_UP = 0,
  BTN_DOWN,
  BTN_SELECT,   // "OK"
  BTN_BACK,     // "Back/Del"
  BTN_LEFT,     // D8
  BTN_RIGHT,    // D9
  BTN_COUNT
};

enum ButtonEvent {
  EV_NONE = 0,
  EV_PRESS,        // clean short press (fires on release, or on repeat tick)
  EV_LONGPRESS     // held past BTN_LONGPRESS_MS (fires once)
};

struct ButtonAction {
  ButtonId    id;
  ButtonEvent event;
};

class Buttons {
public:
  void begin();

  // Poll once per loop iteration. Returns true and fills `out` when an event
  // is available; returns false when nothing happened this tick.
  bool poll(ButtonAction &out);

private:
  struct State {
    uint8_t  pin;
    bool     stableDown;      // debounced logical state (true = pressed)
    bool     lastRaw;         // last raw reading
    uint32_t lastChangeMs;    // for debounce
    uint32_t downSinceMs;     // when the debounced press began
    bool     longFired;       // long-press already reported for this hold
    uint32_t nextRepeatMs;    // next auto-repeat deadline
  };
  State st_[BTN_COUNT];
};
