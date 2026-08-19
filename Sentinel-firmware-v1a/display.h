#pragma once
//
// Thin wrapper over U8g2 for the SSD1306 OLED. Keeps U8g2 details out of the
// application code and provides a few reusable screens.

#include <U8g2lib.h>
#include "i18n.h"

class Display {
public:
  void begin();

  // Selects which font variant every text-drawing call below uses (see
  // font4x6_()/font5x7_()/font6x12_()/font7x13B_() and their doc comment) -
  // call whenever the active language changes (boot, and right after the
  // Language screen commits a new choice). Cosmetic-only; doesn't affect
  // any already-drawn frame until the next draw call.
  void setLanguage(uint8_t lang) { lang_ = lang; }

  // Centered title + subtitle boot screen.
  void splash(const char *title, const char *subtitle);

  // Horizontal icon dock (home screen). 5 fixed slots: Coin, Lock, Settings,
  // Battery, Power Off. `selected` is 0-4; `coinTicker` is always shown in
  // the coin slot icon; `label` is the text shown at the bottom of the
  // screen. Pass `bleOn` (Bluetooth radio enabled - the indicator is shown
  // whenever on, regardless of connection state, as "BT") / `bleConnected`
  // (a device is actually connected - shows "-BT-" instead) / `usbConn`
  // (actually connected, shows "USB") to drive the top-right indicator, and
  // `batteryPct` (0-100) to set the Battery slot's icon fill level.
  // `showCoinArrows` hides the coin slot's up/down cycling-hint arrows when
  // there are fewer than 2 coins to cycle through (0 or 1 active coins) -
  // no point hinting at a gesture that can't actually change anything.
  void homeMenu(uint8_t selected, const char *coinTicker, const char *label,
                bool bleOn = false, bool bleConnected = false, bool usbConn = false,
                uint8_t batteryPct = 100, bool showCoinArrows = true);

  // Scrollable list menu with an inverted title bar and a '>' cursor.
  // `activeIndex` (0xFF = none) draws a small checkmark next to that one
  // row - the "this is the currently-set value" indicator, independent of
  // `selected` (the cursor position, which the user can move without
  // changing the actual setting).
  void menu(const char *title, const char *const *items, uint8_t count, uint8_t selected,
            uint8_t activeIndex = 0xFF);

  // A settings-list row: either a plain action label (isToggle=false, e.g.
  // "Reset Wallet") or a toggle (isToggle=true, `on` is its current state,
  // drawn as a small ON/OFF switch graphic instead of text).
  struct SettingsRow {
    const char *label;
    bool        isToggle;
    bool        on;
  };

  // Same title-bar + '>' cursor list as menu(), but for a mix of toggle
  // and plain-action rows. When `animKnobPos` is >= 0, the *selected*
  // row's knob is drawn at that fractional position (0=OFF..1=ON) instead
  // of snapping straight to its `on` value - lets a caller play a short
  // slide animation by calling this repeatedly with intermediate values
  // before committing the real new state (see coldwallet.ino's
  // animateToggleRow()).
  void settingsMenu(const char *title, const SettingsRow *rows, uint8_t count,
                     uint8_t selected, float animKnobPos = -1.0f);

  // Title bar + body. Body may contain '\n' to break lines (no auto-wrap).
  // `centered` horizontally centers each body line under the title bar
  // (the title bar text itself always stays left-aligned); left-aligned
  // body (the default) otherwise.
  void message(const char *title, const char *body, bool centered = false);

  // Seed backup word page: title bar ("Word N / 24"), the word itself in a
  // larger bold font, centered in the space below the title bar (title
  // bar's own height excluded from the centering math). Prev/Next are
  // small triangle arrows flanking the word directly, not text labels —
  // `showPrev`/`showNext` control whether each is drawn (hidden on the
  // first/last word respectively). When `showDoneHint` is true (the last
  // word), "Hold OK to continue" is pinned at the very bottom — finishing
  // the review is always hold-OK regardless of whether this hint is shown.
  void seedWordPage(const char *title, const char *word, bool showPrev, bool showNext,
                     bool showDoneHint = false);

  // A centered message() page (see `centered` above) with the same
  // edge-pinned Prev/Next triangle arrows as seedWordPage() — used for a
  // paged multi-screen sequence (e.g. the pre-generation "Important"
  // warning pages) navigated by Left/Right rather than tapping OK.
  void importantPage(const char *title, const char *body, bool showPrev, bool showNext);

  // BIP39 letter-cycling word-entry screen: title bar, then the typed
  // prefix (`typedLine`) and the live top-matching word (`matchLine`) in
  // the normal body font, then a `hint` line in a smaller font centered
  // near the bottom — visually separates the button instructions from the
  // actual content instead of cramming both into one plain text size.
  void wordEntryPage(const char *title, const char *typedLine, const char *matchLine,
                      const char *hint);

  // No title bar — every '\n'-separated line is horizontally centered, and
  // the whole block is vertically centered on the panel. Used for a screen
  // that's just standalone centered text (e.g. About), not an
  // action/status message anchored under a title.
  void centeredMessage(const char *body);

  // A single centered message line (e.g. "Adding Bitcoin Network") + a
  // filled progress bar with an "NN%" readout centred inside it. `pct` is
  // clamped to 0..100. The bar-fill loop lives in coldwallet.ino, not here —
  // see startLoadingAnimation()'s own comment for why it's a real animation
  // (a second FreeRTOS task redrawing on a timer) rather than a single
  // static draw: address derivation is a genuinely slow (measured up to
  // ~2.1s for ADA), CPU-bound, single blocking call with no natural
  // progress checkpoints inside it to hook a real percentage into.
  void loading(const char *message, uint8_t pct);

  // Coin icon centered near the top, then up to two centered text lines
  // (title, optional body), then either a hint line (may itself contain one
  // '\n') or, when `iconHint` is true, a back-arrow icon (bottom-left) and
  // an OK checkmark icon (bottom-right) instead of text - `hint` is ignored
  // in that mode. Used for the app-driven "Open <Coin>" sign-select
  // confirmation (icon mode) and the per-coin About screen (text mode,
  // empty hint).
  void coinPrompt(const char *ticker, const char *title, const char *body,
                   const char *hint, bool iconHint = false);

  // Coin icon + centered "<Coin> is ready" body, with a small down-arrow
  // pinned at the bottom (press DOWN to open the Receive/Settings menu).
  void coinReady(const char *ticker, const char *body);

  // A small up-arrow at the top (press UP to return to the coin-ready
  // screen) followed by a plain selectable list (no title bar) - used for
  // the coin-ready page's Receive/Settings drill-down menu.
  void arrowMenu(const char *const *items, uint8_t count, uint8_t selected);

  // Horizontal-ruler PIN entry. Digits 0-9 plus an OK circle on the right.
  // `curPos` 0-9 = highlighted digit, 10 = OK circle selected.
  // OK circle is filled when `canConfirm` is true (enough digits entered).
  void pinEntry(const char *title, const char *stars, uint8_t curPos, bool canConfirm);

  // Render `text` as a QR code, centered and scaled to fit the panel. Drawn as
  // dark modules on a lit background so a phone camera can read it.
  void qr(const char *text);

  // Power the OLED panel down (sleep) or back up. setPowerSave(1) issues the
  // SSD1306 "display off" (panel + charge pump off → ~0 mA); the frame buffer is
  // retained, so wake() — or any later draw — restores the last image.
  void sleep() { u8g2_.setPowerSave(1); }
  void wake()  { u8g2_.setPowerSave(0); }

private:
  // SIDE RELEASE: display mounted rotated 180° on this board revision
  // (OLED pins moved from top to bottom) - U8G2_R2 rotates the panel
  // output 180° in software to compensate. Do not port this to the main
  // firmware/coldwallet/ tree - it's specific to this hardware variant.
  U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2_ =
      U8G2_SSD1306_128X64_NONAME_F_HW_I2C(U8G2_R2, U8X8_PIN_NONE);

  uint8_t lang_ = 0;   // i18n::LANG_EN

  // Every text-drawing function uses these instead of a hardcoded
  // u8g2_font_*_tr constant directly, so translated (accented Latin or
  // Cyrillic) strings render correctly under the active language: Russian
  // (i18n::LANG_RU) gets the matching "_t_cyrillic" sibling (or, for the
  // bold 7x13B weight - which has no same-size Cyrillic sibling in this
  // vendored u8g2 - the closest bold Cyrillic font, 6x13B); every other
  // language uses the "_tf" (full Latin-1) sibling of the plain ASCII
  // "_tr" font this app used before localization, which is a strict glyph
  // superset of "_tr" so plain English text still renders identically.
  // Every glyph these translated strings actually use was verified present
  // in the real font binary data before this file was written - see
  // i18n.cpp's own header comment.
  const uint8_t *font4x6_()   const { return u8g2_font_4x6_tf; }
  const uint8_t *font5x7_()   const;
  const uint8_t *font6x12_()  const;
  const uint8_t *font7x13B_() const;

  void drawTitleBar_(const char *title);

  // Small rounded ON/OFF toggle switch (track + sliding knob), for
  // settingsMenu(). `pos` is 0.0 (OFF, knob left) to 1.0 (ON, knob right).
  void drawToggle_(uint8_t x, uint8_t y, float pos);

  // Small checkmark (short down-stroke then longer up-stroke), for menu()'s
  // `activeIndex` row indicator, and reused as coinPrompt()'s "OK" icon.
  // (x,y) is the checkmark's top-left corner.
  void drawCheckmark_(uint8_t x, uint8_t y);

  // Small leftward-pointing chevron ("<"), for coinPrompt()'s icon-hint
  // mode "back/cancel" indicator. (x,y) is its top-left corner.
  void drawBackArrowIcon_(uint8_t x, uint8_t y);

  // Icon drawing helpers for homeMenu (icons are 16x16, placed at (x,y)).
  void drawCoinIcon_   (uint8_t x, uint8_t y, const char *ticker, bool inv = false);
  void drawLockIcon_   (uint8_t x, uint8_t y, bool inv = false);
  void drawSettingsIcon_(uint8_t x, uint8_t y, bool inv = false);
  void drawBatteryIcon_(uint8_t x, uint8_t y, uint8_t pct, bool inv = false);
  void drawPowerIcon_  (uint8_t x, uint8_t y, bool inv = false);
};
