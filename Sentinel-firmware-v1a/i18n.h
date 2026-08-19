#pragma once
//
// Firmware UI localization. Scoped deliberately: only the recurring
// runtime screens (home menu, unlock, Settings + its sub-flows) are
// translated - NOT the one-time first-boot setup wizard (the device's
// language is itself a Settings choice, so it can't meaningfully apply to
// screens shown before Settings is ever reached), and NOT coin/ticker
// names (kept as-is everywhere, same as the companion app).
//
// Only languages whose script the OLED's u8g2 fonts can actually render
// are wired up: English, Spanish, Portuguese, Estonian (all Latin-1 - a
// same-metrics "_tf" sibling of every font size already in use, verified
// against the real u8g2 font binary data to contain every accented
// character these translations need), and Russian (Cyrillic - matching
// "_t_cyrillic" siblings exist for the 5x7/6x12 body fonts and a 6x13B
// bold substitute for 7x13B, verified to contain the full Cyrillic
// alphabet plus every digit/punctuation character these strings need).
// Vietnamese/Hindi/Arabic/Korean/Japanese/Chinese need either a real
// script-shaping engine (Arabic/Hindi) or much bigger glyphs with a full
// per-screen layout rework (Vietnamese/Korean/Japanese/Chinese) - out of
// scope for this pass; `tr()` falls back to English for those.

#include <stdint.h>

namespace i18n {

// Matches kLanguageLabels' index order in coldwallet.ino (store::language()'s
// own encoding) - only the first 5 are actually translated.
enum Lang : uint8_t {
  LANG_EN = 0,
  LANG_ES = 1,
  LANG_PT = 2,
  LANG_ET = 3,
  LANG_RU = 4,
  LANG_SUPPORTED_COUNT = 5,
};

enum StrId : uint8_t {
  S_SETTINGS,
  S_LOCK_DEVICE,
  S_POWER_OFF,
  S_INSTALL_COINS,
  S_BATTERY,
  S_BATTERY_SAVER,
  S_LANGUAGE,
  S_DEVICE_INFORMATION,
  S_UNINSTALL_ALL_COINS,
  S_CHANGE_PIN,
  S_RESET_DEVICE,
  S_OFF,
  S_1_MINUTE,
  S_3_MINUTES,
  S_5_MINUTES,
  S_10_MINUTES,
  S_FIRMWARE,
  S_ENTER_PIN,
  S_WIPED,
  S_TOO_MANY_TRIES,
  S_DENIED,
  S_WRONG_PIN_LINE,
  S_TRIES_LEFT,
  S_ERROR,
  S_STORAGE_FAULT,
  S_UNINSTALLED,
  S_ALL_COINS_REMOVED,
  S_HOLD_OK_UNINSTALL_ALL,
  S_CURRENT_PIN,
  S_NEW_PIN,
  S_CONFIRM_PIN,
  S_CANCELLED,
  S_PIN_UNCHANGED,
  S_WRONG_PIN,
  S_MISMATCH,
  S_TRY_AGAIN,
  S_PIN_CHANGED,
  S_NEW_PIN_SAVED,
  S_HOLD_OK_SET_NEW_PIN,
  S_HOLD_OK_RESET_DEVICE,
  S_RESET_ABORTED,
  S_RESET_CANCELLED,
  S_RESET,
  S_DEVICE_ERASED_REBOOTING,
  S_COUNT
};

// Returns the string for `id` in `lang`; any language outside
// LANG_SUPPORTED_COUNT (Vietnamese onward) falls back to English.
const char *tr(uint8_t lang, StrId id);

}  // namespace i18n
