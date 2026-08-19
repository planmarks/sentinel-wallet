#include "display.h"
#include "config.h"
#include <Wire.h>
#include <string.h>
#include "qrcodegen.h"    // vendored ricmoo/QRCode (renamed to avoid a qrcode.h name clash)

// Layout constants for the 128x64 panel with the 6x12 font.
static const uint8_t TITLE_H   = 13;   // height of the inverted title bar
static const uint8_t LINE_H    = 12;   // per-row height in the body
static const uint8_t BODY_TOP  = TITLE_H + LINE_H;  // baseline of first body row
static const uint8_t MENU_ROWS = 4;    // visible menu items at once

void Display::begin() {
  Wire.begin();                          // XIAO default I2C: SDA=D4, SCL=D5
  u8g2_.setI2CAddress(OLED_I2C_ADDR8);
  u8g2_.begin();
  u8g2_.setBusClock(400000);
  u8g2_.enableUTF8Print();
}

const uint8_t *Display::font5x7_() const {
  return (lang_ == i18n::LANG_RU) ? u8g2_font_5x7_t_cyrillic : u8g2_font_5x7_tf;
}
const uint8_t *Display::font6x12_() const {
  return (lang_ == i18n::LANG_RU) ? u8g2_font_6x12_t_cyrillic : u8g2_font_6x12_tf;
}
const uint8_t *Display::font7x13B_() const {
  // No same-size ("7x13B") bold Cyrillic sibling exists in this vendored
  // u8g2 - 6x13B is the closest bold Cyrillic font (1px narrower, same
  // height), used for Russian; every other language keeps the real 7x13B.
  return (lang_ == i18n::LANG_RU) ? u8g2_font_6x13B_t_cyrillic : u8g2_font_7x13B_tf;
}

void Display::drawTitleBar_(const char *title) {
  u8g2_.setDrawColor(1);
  u8g2_.drawBox(0, 0, OLED_WIDTH, TITLE_H);
  u8g2_.setDrawColor(0);
  u8g2_.setFont(font6x12_());
  u8g2_.drawUTF8(2, TITLE_H - 3, title);
  u8g2_.setDrawColor(1);
}

// ---- Home-menu (horizontal icon dock) ----------------------------------------
//
// Layout (128x64):
//   y=0..51  : icon area — 5 icons, each 16x16, centred vertically at y=26
//   y=53..63 : label strip

static const uint8_t HM_ICON_TOP = 18;   // y of icon top edge
static const uint8_t HM_LABEL_Y  = 60;   // text baseline (3 px margin for descenders)
// X centre of each of the 5 slots (even distribution across 128 px). The
// coin slot (index 0) is nudged 1px right of its even-spacing position
// (15->16) for 1px more breathing room from the left nav arrow, which sits
// right at the screen edge (x=0) and can't itself move any further left.
static const uint8_t HM_CX[5]   = { 16, 39, 64, 89, 113 };

// For each icon function: `inv=false` → normal (white on black);
//                         `inv=true`  → inverted (black on white background disc).
// Callers must pre-fill the disc with color 1 before calling with inv=true.

// No background badge/circle — bold "B" glyph. Both counters (holes) now
// have a flat left edge and a round right edge ("D" shaped, not a plain
// ellipse), and it has a small tail/foot extending left at both the top
// and bottom of the glyph, symmetric top and bottom.
static const uint8_t coinIcon_BTC_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x40, 0x04, 0x00,
  0x40, 0x04, 0x00,
  0xF8, 0x0F, 0x00,
  0xE0, 0x18, 0x00,
  0xE0, 0x10, 0x00,
  0xE0, 0x10, 0x00,
  0xE0, 0x18, 0x00,
  0xE0, 0x0F, 0x00,
  0xE0, 0x3F, 0x00,
  0xE0, 0x70, 0x00,
  0xE0, 0x60, 0x00,
  0xE0, 0x60, 0x00,
  0xE0, 0x70, 0x00,
  0xF8, 0x3F, 0x00,
  0x40, 0x04, 0x00,
  0x40, 0x04, 0x00,
  0x00, 0x00, 0x00,
};

// Corrected: the previous version flipped the bottom piece upside down
// (point-up), which was wrong — both pieces keep their natural diamond-
// half orientation (kite pointing outward, tip away from the gap). The
// upside-down-triangle look comes purely from the gap itself: the top
// kite's own lower sides converge to a point, and the bottom kite's wide
// top edge sits below it, so the empty space between them widens toward
// the top and narrows to a point — without either piece itself being a
// triangle.
static const uint8_t coinIcon_ETH_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x01, 0x00,
  0x80, 0x03, 0x00,
  0x80, 0x03, 0x00,
  0xC0, 0x07, 0x00,
  0xE0, 0x0F, 0x00,
  0xF0, 0x1F, 0x00,
  0xF0, 0x1F, 0x00,
  0xF8, 0x3F, 0x00,
  0xC0, 0x07, 0x00,
  0x00, 0x01, 0x00,
  0x00, 0x00, 0x00,
  0xE0, 0x0F, 0x00,
  0xC0, 0x07, 0x00,
  0x80, 0x03, 0x00,
  0x80, 0x03, 0x00,
  0x00, 0x01, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_SOL_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xF0, 0xFF, 0x00,
  0xF8, 0x7F, 0x00,
  0xFC, 0x3F, 0x00,
  0x00, 0x00, 0x00,
  0xFC, 0x1F, 0x00,
  0xF8, 0x3F, 0x00,
  0xF0, 0x7F, 0x00,
  0xE0, 0xFF, 0x00,
  0x00, 0x00, 0x00,
  0xF0, 0xFF, 0x00,
  0xF8, 0x7F, 0x00,
  0xFC, 0x3F, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_XLM_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x80, 0x07, 0x00,
  0xE0, 0x0C, 0x01,
  0x30, 0xC0, 0x00,
  0x18, 0x30, 0x00,
  0x08, 0x0C, 0x01,
  0x0C, 0xC3, 0x00,
  0xC4, 0xF0, 0x00,
  0x3C, 0x8C, 0x00,
  0x0C, 0xC3, 0x00,
  0xC2, 0x40, 0x00,
  0x30, 0x60, 0x00,
  0x0C, 0x30, 0x00,
  0xC2, 0x1C, 0x00,
  0x80, 0x07, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Center pixels removed entirely (were two stray single pixels between the
// ring-of-6 dots, unnecessary clutter); top/bottom tiny-dot pair kept at
// the same outer radius as the 4 diagonal corner dots.
static const uint8_t coinIcon_ADA_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x01, 0x00,
  0x00, 0x00, 0x00,
  0x08, 0x40, 0x00,
  0x40, 0x08, 0x00,
  0xE0, 0x1C, 0x00,
  0x40, 0x08, 0x00,
  0x10, 0x20, 0x00,
  0x38, 0x70, 0x00,
  0x10, 0x20, 0x00,
  0x00, 0x00, 0x00,
  0x40, 0x08, 0x00,
  0xE0, 0x1C, 0x00,
  0x40, 0x08, 0x00,
  0x08, 0x40, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x01, 0x00,
  0x00, 0x00, 0x00,
};

// Real XRP mark: not filled triangles - two mirrored diagonal strokes
// ("V"/"^" lines) that start thin at the outer top/bottom corners and
// widen as they approach the center, merging into one wider blunt tip
// right at the gap (wider than a regular uniform-width V there). Strokes
// themselves thinned (2px arms instead of 3px).
static const uint8_t coinIcon_XRP_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x18, 0x60, 0x00,
  0x30, 0x30, 0x00,
  0x60, 0x18, 0x00,
  0xC0, 0x0C, 0x00,
  0x80, 0x07, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x80, 0x07, 0x00,
  0xC0, 0x0C, 0x00,
  0x60, 0x18, 0x00,
  0x30, 0x30, 0x00,
  0x18, 0x60, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Real TON/GRAM mark: a rounded top bar that splits into 3 separate bands
// (left wing, center stem, right wing) with 2 triangular cutout notches
// between them, converging to a single point at the bottom - not a solid
// badge blob. No background circle, per this set's convention. Notches
// widened significantly (measured off the real logo: gap is roughly
// double each band's own width, not equal to it) so they read as
// deliberate cutouts instead of thin noise slits.
// Diagonal wings continue narrowing straight through the merge into the
// tip - no flat vertical stem padding after the merge. Taper shifts 1
// column every 2 rows so it spans nearly the icon's full height,
// matching the real logo's near-square proportions. All strokes (bar,
// wings, stem) thinned to 1px, uniformly.
static const uint8_t coinIcon_GRAM_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xF8, 0x7F, 0x00,
  0x04, 0x83, 0x00,
  0x04, 0x83, 0x00,
  0x08, 0x43, 0x00,
  0x08, 0x43, 0x00,
  0x10, 0x23, 0x00,
  0x10, 0x23, 0x00,
  0x20, 0x13, 0x00,
  0x20, 0x13, 0x00,
  0x40, 0x0B, 0x00,
  0x40, 0x0B, 0x00,
  0x80, 0x07, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_DOT_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x80, 0x07, 0x00,
  0xC0, 0x0F, 0x00,
  0x90, 0x27, 0x00,
  0x3C, 0xF0, 0x00,
  0x1C, 0xE0, 0x00,
  0x1E, 0xE0, 0x01,
  0x0C, 0xC0, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x0C, 0xC0, 0x00,
  0x1E, 0xE0, 0x01,
  0x1C, 0xE0, 0x00,
  0x3C, 0xF0, 0x00,
  0x90, 0x27, 0x00,
  0xC0, 0x0F, 0x00,
  0x80, 0x07, 0x00,
  0x00, 0x00, 0x00,
};

// Real Tether mark: a "T" (wide top bar + vertical stem) with a thin
// ellipse ring crossing horizontally through it, no background badge.
static const uint8_t coinIcon_USDTTRX_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xF8, 0x7F, 0x00,
  0xF8, 0x7F, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x80, 0x07, 0x00,
  0xF8, 0x7F, 0x00,
  0x0C, 0xC3, 0x00,
  0x06, 0x83, 0x01,
  0x0C, 0xC3, 0x00,
  0xF8, 0x7F, 0x00,
  0x80, 0x07, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Real Litecoin mark: a stylized "Ł" - a tilted diagonal stem (leaning
// left going down) with a short strike-tick poking out partway down, and
// a horizontal foot/base at the bottom. No background, per this set's
// convention.
static const uint8_t coinIcon_LTC_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x06, 0x00,
  0x00, 0x06, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x80, 0x01, 0x00,
  0x80, 0x01, 0x00,
  0xF0, 0x07, 0x00,
  0xC0, 0x00, 0x00,
  0x60, 0x00, 0x00,
  0x60, 0x00, 0x00,
  0xF0, 0x3F, 0x00,
  0xF0, 0x3F, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Real Dogecoin mark (the actual coin symbol, not the meme dog face - the
// dog face doesn't survive at this resolution anyway) is a stylized "Đ":
// a "D" with a flat-left/round-right counter (same shape family as BTC's
// "B") plus a horizontal strike through the stem. No background.
static const uint8_t coinIcon_DOGE_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xF0, 0x0F, 0x00,
  0xF0, 0x1F, 0x00,
  0x70, 0x38, 0x00,
  0x70, 0x30, 0x00,
  0x70, 0x70, 0x00,
  0xFE, 0x73, 0x00,
  0xFE, 0x73, 0x00,
  0x70, 0x70, 0x00,
  0x70, 0x30, 0x00,
  0x70, 0x38, 0x00,
  0xF0, 0x1F, 0x00,
  0xF0, 0x0F, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_DASH_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xE0, 0x3F, 0x00,
  0xC0, 0xFF, 0x00,
  0x00, 0xF0, 0x00,
  0x00, 0xE0, 0x00,
  0xF8, 0xE1, 0x00,
  0xFC, 0xF1, 0x00,
  0x00, 0xF0, 0x00,
  0x00, 0x78, 0x00,
  0xE0, 0x7F, 0x00,
  0xF0, 0x3F, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_SUI_[] PROGMEM = {
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x80, 0x07, 0x00,
  0xC0, 0x0C, 0x00,
  0x60, 0x18, 0x00,
  0x70, 0x30, 0x00,
  0x70, 0x20, 0x00,
  0xD8, 0x60, 0x00,
  0x88, 0x41, 0x00,
  0x08, 0x47, 0x00,
  0x08, 0x4E, 0x00,
  0x18, 0x6C, 0x00,
  0x18, 0x78, 0x00,
  0x30, 0x38, 0x00,
  0xE0, 0x1F, 0x00,
  0xC0, 0x0F, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_NEAR_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x38, 0x60, 0x00,
  0x38, 0x70, 0x00,
  0x78, 0x78, 0x00,
  0xD8, 0x68, 0x00,
  0x98, 0x61, 0x00,
  0x98, 0x63, 0x00,
  0x18, 0x67, 0x00,
  0x18, 0x66, 0x00,
  0x58, 0x6C, 0x00,
  0x78, 0x78, 0x00,
  0x38, 0x70, 0x00,
  0x18, 0x70, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_ALGO_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x1C, 0x00,
  0x00, 0x1E, 0x00,
  0x00, 0x1E, 0x00,
  0x00, 0x7F, 0x00,
  0x80, 0x7B, 0x00,
  0x80, 0x31, 0x00,
  0xC0, 0x39, 0x00,
  0xE0, 0x38, 0x00,
  0xE0, 0x7C, 0x00,
  0x60, 0x7E, 0x00,
  0x30, 0x66, 0x00,
  0x38, 0x67, 0x00,
  0xB8, 0xE3, 0x00,
  0x9C, 0xE3, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Same as BTC's bold "B" glyph, rotated ~10 degrees left (counter-
// clockwise), matching how the real Bitcoin Cash mark is a tilted
// version of the Bitcoin symbol.
static const uint8_t coinIcon_BCH_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x02, 0x00,
  0x20, 0x02, 0x00,
  0xE0, 0x0F, 0x00,
  0x7C, 0x08, 0x00,
  0x70, 0x18, 0x00,
  0xE0, 0x18, 0x00,
  0xE0, 0x08, 0x00,
  0xE0, 0x3F, 0x00,
  0xE0, 0x7F, 0x00,
  0xE0, 0x60, 0x00,
  0xE0, 0xC0, 0x00,
  0xC0, 0xE1, 0x00,
  0xC0, 0x71, 0x00,
  0xC0, 0x1F, 0x00,
  0xF0, 0x08, 0x00,
  0x80, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_RVN_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x06, 0x00,
  0x00, 0x1F, 0x00,
  0x80, 0x0F, 0x00,
  0x80, 0x0F, 0x00,
  0x80, 0x0F, 0x00,
  0xC0, 0x1F, 0x00,
  0xC0, 0x1F, 0x00,
  0xC0, 0x1F, 0x00,
  0xC0, 0x0F, 0x00,
  0xE0, 0x0F, 0x00,
  0xE0, 0x0F, 0x00,
  0xE0, 0x0F, 0x00,
  0xE0, 0x07, 0x00,
  0xE0, 0x00, 0x00,
  0x30, 0x00, 0x00,
  0x10, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_TRX_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x1C, 0x00, 0x00,
  0xFC, 0x03, 0x00,
  0x1C, 0x3C, 0x00,
  0x28, 0x70, 0x00,
  0xC8, 0x8C, 0x00,
  0x98, 0xF7, 0x00,
  0x10, 0xCF, 0x00,
  0x10, 0x41, 0x00,
  0x20, 0x21, 0x00,
  0x20, 0x11, 0x00,
  0x60, 0x09, 0x00,
  0x40, 0x0D, 0x00,
  0xC0, 0x05, 0x00,
  0x80, 0x03, 0x00,
  0x80, 0x01, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_APT_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0xC0, 0x0F, 0x00,
  0xF0, 0x3F, 0x00,
  0x00, 0x04, 0x00,
  0x00, 0x04, 0x00,
  0x00, 0x0E, 0x00,
  0xFE, 0xFD, 0x01,
  0xFE, 0xF8, 0x01,
  0x80, 0x00, 0x00,
  0x80, 0x01, 0x00,
  0xFE, 0xFF, 0x01,
  0x9E, 0xFF, 0x01,
  0x10, 0x00, 0x00,
  0x30, 0x00, 0x00,
  0x30, 0x00, 0x00,
  0xF0, 0x3F, 0x00,
  0xC0, 0x0F, 0x00,
  0x00, 0x00, 0x00,
};

// Real ATOM/Cosmos Hub mark is the classic "atom" symbol: 3 elliptical
// orbit rings, each rotated 60 deg from the next, crossing through a
// filled center nucleus dot. Previous version was just a solid blob
// circle - rebuilt from scratch as 3 true rotated ellipses (parametric,
// not a downsampled trace) plus a 2x2 center dot.
static const uint8_t coinIcon_ATOM_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xF0, 0x3C, 0x00,
  0x90, 0x27, 0x00,
  0x90, 0x27, 0x00,
  0xD0, 0x2F, 0x00,
  0xF8, 0x7C, 0x00,
  0x7E, 0xF8, 0x01,
  0x22, 0x13, 0x01,
  0x22, 0x13, 0x01,
  0x7E, 0xF8, 0x01,
  0xF8, 0x7C, 0x00,
  0xD0, 0x2F, 0x00,
  0x90, 0x27, 0x00,
  0x90, 0x27, 0x00,
  0xF0, 0x3C, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Real DigiByte mark, traced directly from the actual logo (CoinGecko
// source image, cropped to the glyph and resized) rather than hand-
// composed - the hand-built version kept drifting from the source.
// Reads as a bold italic "D": a wide slanted top cap, a diagonal
// stem+bowl with a counter hole, tapering to a slanted bottom, with
// tick marks above and below. No background.
static const uint8_t coinIcon_DGB_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x1B, 0x00,
  0xF8, 0x3F, 0x00,
  0xFC, 0xFF, 0x00,
  0xFC, 0xFF, 0x00,
  0xC0, 0xF0, 0x00,
  0xE0, 0xF0, 0x00,
  0xF0, 0xF0, 0x00,
  0x70, 0x78, 0x00,
  0x70, 0x7C, 0x00,
  0x78, 0x3E, 0x00,
  0xF8, 0x1F, 0x00,
  0xFC, 0x07, 0x00,
  0xFC, 0x00, 0x00,
  0x70, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_FIL_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x3C, 0x00,
  0x00, 0x26, 0x00,
  0x00, 0x02, 0x00,
  0x00, 0x03, 0x00,
  0xE0, 0x03, 0x00,
  0x80, 0x0F, 0x00,
  0x00, 0x03, 0x00,
  0xE0, 0x03, 0x00,
  0x00, 0x0F, 0x00,
  0x80, 0x01, 0x00,
  0x80, 0x01, 0x00,
  0x80, 0x00, 0x00,
  0xC0, 0x00, 0x00,
  0x78, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_BABY_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x10, 0x20, 0x00,
  0x78, 0x78, 0x00,
  0xFC, 0xFF, 0x00,
  0xFE, 0xFF, 0x01,
  0xDC, 0xEC, 0x00,
  0x1C, 0xE0, 0x00,
  0x3C, 0xF0, 0x00,
  0x18, 0x60, 0x00,
  0x18, 0x60, 0x00,
  0x3C, 0xF0, 0x00,
  0x1C, 0xE0, 0x00,
  0xDC, 0xEC, 0x00,
  0xFE, 0xFF, 0x01,
  0xFC, 0xFF, 0x00,
  0x78, 0x78, 0x00,
  0x10, 0x20, 0x00,
  0x00, 0x00, 0x00,
};

// Kept the existing diamond/X shape as-is; the old middle rows (8-9) had
// an accidental asymmetric notch (row9 didn't mirror row7). Replaced
// with a clean, deliberate 1px gap at the exact center row (row8 only),
// symmetric top/bottom.
static const uint8_t coinIcon_AXL_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x10, 0x00,
  0x30, 0x38, 0x00,
  0x78, 0x7C, 0x00,
  0xFC, 0xFE, 0x00,
  0xFE, 0xFF, 0x00,
  0xFC, 0x7F, 0x00,
  0xF8, 0x3F, 0x00,
  0xF8, 0x3E, 0x00,
  0xF8, 0x3F, 0x00,
  0xFC, 0x7F, 0x00,
  0xFE, 0xFF, 0x00,
  0xFC, 0xFE, 0x00,
  0x78, 0x7C, 0x00,
  0x30, 0x38, 0x00,
  0x00, 0x10, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

// Real dYdX mark: an "X" where the top-right-to-bottom-left diagonal is
// fully continuous/unbroken the whole way through, while the top-left-
// to-bottom-right diagonal has a real gap on both sides of the first
// line - it stops short before the crossing and resumes after, never
// touching the continuous line. Top and bottom halves are symmetric.
static const uint8_t coinIcon_DYDX_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0x38, 0x70, 0x00,
  0x70, 0x38, 0x00,
  0x70, 0x38, 0x00,
  0xE0, 0x1C, 0x00,
  0xC0, 0x0E, 0x00,
  0x40, 0x0E, 0x00,
  0x00, 0x07, 0x00,
  0x80, 0x03, 0x00,
  0xC0, 0x09, 0x00,
  0xC0, 0x0D, 0x00,
  0xE0, 0x1C, 0x00,
  0x70, 0x38, 0x00,
  0x70, 0x38, 0x00,
  0x38, 0x70, 0x00,
  0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t coinIcon_TIA_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0xC0, 0x0F, 0x00,
  0x70, 0x3C, 0x00,
  0xF8, 0x63, 0x00,
  0x0C, 0xEF, 0x00,
  0x04, 0xF9, 0x00,
  0x06, 0xF1, 0x01,
  0x06, 0xFD, 0x01,
  0x0E, 0xC7, 0x01,
  0x8A, 0xC1, 0x01,
  0x72, 0xE1, 0x01,
  0x76, 0x71, 0x01,
  0xDC, 0xED, 0x00,
  0x8C, 0xFF, 0x00,
  0xF8, 0x72, 0x00,
  0x30, 0x36, 0x00,
  0xC0, 0x0F, 0x00,
  0x00, 0x00, 0x00,
};

// `size` lets each icon use a canvas bigger than the nominal 16x16 slot
// (e.g. BTC's 22x22) without needing a separate draw path per icon —
// drawCoinIcon_ centres whatever size it's given on the slot automatically.
struct CoinIconEntry { const char *ticker; const uint8_t *bitmap; uint8_t size; };
static const CoinIconEntry COIN_ICONS[] = {
  {"BTC", coinIcon_BTC_, 18},
  {"ETH", coinIcon_ETH_, 18},
  {"SOL", coinIcon_SOL_, 18},
  {"XLM", coinIcon_XLM_, 18},
  {"ADA", coinIcon_ADA_, 18},
  {"XRP", coinIcon_XRP_, 18},
  {"ATOM", coinIcon_ATOM_, 18},
  {"TRX", coinIcon_TRX_, 18},
  {"GRAM", coinIcon_GRAM_, 18},
  {"DOT", coinIcon_DOT_, 18},
  // Keyed "USDT", not "USDTTRX" - the home menu's ticker comes from
  // coinLabel(), which deliberately displays "USDT" for COIN_USDTTRX (the
  // TRC-20 network is shown separately in the picker, not in this label).
  // The old "USDTTRX" key never matched anything drawCoinIcon_ was ever
  // actually called with, so this icon was silently dead code.
  {"USDT", coinIcon_USDTTRX_, 18},
  {"LTC", coinIcon_LTC_, 18},
  {"DOGE", coinIcon_DOGE_, 18},
  {"DASH", coinIcon_DASH_, 18},
  {"DGB", coinIcon_DGB_, 18},
  {"RVN", coinIcon_RVN_, 18},
  {"SUI", coinIcon_SUI_, 18},
  {"APT", coinIcon_APT_, 18},
  {"NEAR", coinIcon_NEAR_, 18},
  {"ALGO", coinIcon_ALGO_, 18},
  {"DYDX", coinIcon_DYDX_, 18},
  {"AXL", coinIcon_AXL_, 18},
  {"BABY", coinIcon_BABY_, 18},
  {"BCH", coinIcon_BCH_, 18},
  {"TIA", coinIcon_TIA_, 18},
  {"FIL", coinIcon_FIL_, 18},
};
static const uint8_t COIN_ICON_COUNT = sizeof(COIN_ICONS) / sizeof(COIN_ICONS[0]);

// Real per-coin icons, same generate-verify-then-flash discipline as the
// gear icon — designed and checked for stray/isolated pixels offline
// before ever touching real code — for every coin this firmware can
// install. Falls back to the old generic circle+ticker-text for anything
// not in the table (defensive only — coinName() only ever returns one of
// these 26 strings today).
void Display::drawCoinIcon_(uint8_t x, uint8_t y, const char *ticker, bool inv) {
  // Sentinel ticker for "no coin installed yet" (homeMenu() passes "+" as
  // coinTicker once store::anyCoinActive() is false) - a bold plus glyph,
  // same stroke weight as the other home-menu icons, instead of the
  // circle+truncated-text fallback below (which would otherwise render a
  // meaningless "+" inside a circle).
  if (strcmp(ticker, "+") == 0) {
    // Both bars are centered on the same point (x+7.5, y+7.5) with equal
    // arm lengths on every side (4px) - the first version used mismatched
    // bar lengths/positions that put the crossbar off-center, making the
    // upper and left arms visibly shorter than the lower and right ones.
    // Thinner too (2px, was 3px) per feedback that it read as too bold.
    u8g2_.setDrawColor(inv ? 0 : 1);
    u8g2_.drawBox(x + 7, y + 1, 2, 14);   // vertical bar
    u8g2_.drawBox(x + 1, y + 7, 14, 2);   // horizontal bar
    u8g2_.setDrawColor(1);
    return;
  }
  const uint8_t *bmp = nullptr;
  uint8_t size = 18;
  for (uint8_t i = 0; i < COIN_ICON_COUNT; i++) {
    if (strcmp(ticker, COIN_ICONS[i].ticker) == 0) {
      bmp = COIN_ICONS[i].bitmap;
      size = COIN_ICONS[i].size;
      break;
    }
  }
  if (bmp) {
    u8g2_.setDrawColor(inv ? 0 : 1);
    u8g2_.setBitmapMode(1);
    // Centred on the nominal 16x16 slot regardless of this icon's own size.
    int8_t off = (int8_t)(16 - size) / 2;
    u8g2_.drawXBMP(x + off, y + off, size, size, bmp);
    u8g2_.setDrawColor(1);
    return;
  }
  uint8_t mc = inv ? 0 : 1;   // main draw color
  u8g2_.setDrawColor(mc);
  u8g2_.drawCircle(x + 7, y + 7, 7);
  u8g2_.setFont(font4x6_());
  char buf[5];
  uint8_t n = 0;
  while (ticker[n] && n < 4) { buf[n] = ticker[n]; n++; }
  buf[n] = '\0';
  uint8_t tw = u8g2_.getUTF8Width(buf);
  u8g2_.drawUTF8(x + 7 - tw / 2, y + 10, buf);
  u8g2_.setDrawColor(1);
}

// Padlock: a shackle with genuinely rounded top corners (not a hard-cornered
// U), a rounded-corner body at its original full size, and a classic
// circle-plus-wedge keyhole silhouette (not just a short slot). The two
// corner arcs use the exact same construction u8g2_DrawRFrame() itself uses
// internally (verified directly against its source) — each quarter-circle's
// own leftmost/topmost pixel lands exactly on the straight edge it meets, so
// there's no gap or misalignment between the curve and the legs.
void Display::drawLockIcon_(uint8_t x, uint8_t y, bool inv) {
  u8g2_.setDrawColor(inv ? 0 : 1);
  // Shackle top corners: quarter-circles (r=2) centered 2px in from each
  // leg, so their outer edge lands exactly on the leg's own x position.
  u8g2_.drawCircle(x + 6, y + 3, 2, U8G2_DRAW_UPPER_LEFT);
  u8g2_.drawCircle(x + 8, y + 3, 2, U8G2_DRAW_UPPER_RIGHT);
  u8g2_.drawHLine(x + 7, y + 1, 1);   // 1px connector between the two arc tops
  u8g2_.drawVLine(x + 4, y + 4, 2);   // left leg, continuing from the arc down to the body
  u8g2_.drawVLine(x + 10, y + 4, 2);  // right leg
  u8g2_.drawRBox(x + 2, y + 6, 11, 9, 2); // body — original full size, now rounded-corner
  u8g2_.setDrawColor(inv ? 1 : 0);     // keyhole: punched out, background color
  u8g2_.drawDisc(x + 7, y + 10, 2);    // the round "hole"
  u8g2_.drawTriangle(x + 7, y + 11, x + 6, y + 13, x + 8, y + 13); // widening wedge below it — a touch narrower
  u8g2_.setDrawColor(1);
}

// 8-tooth gear, as a fixed 16x16 bitmap rather than composed from
// primitives. Two prior attempts (5-wide cardinal teeth + separate 2x2
// diagonal boxes; then just 4 thin teeth on a bigger body) both rendered
// wrong on real hardware despite looking reasonable on paper — composing
// a gear from drawDisc/drawBox primitives at this resolution is genuinely
// hard to get pixel-perfect by hand. This bitmap was instead generated by
// simulating full 8-fold-symmetric polar geometry (body radius 5, tooth
// tip radius 7, centre hole radius 2.6) in Python and rasterizing it
// directly, verified as a clean ASCII render before ever touching real
// code — see the "gear_bytes.py" derivation if this needs regenerating.
// 18x18, not 16x16 — a real bug the previous "bigger" attempt had: bumping
// the radii by ~0.2px within the same 16x16 canvas only filled in more of
// the interior (thicker teeth/body), since the outer tip radius was already
// close to the max that fits in 16px — it barely extended the actual
// silhouette. A genuinely bigger icon needs a bigger canvas: body radius 6,
// tooth tip radius 8, centre hole radius 3, re-verified artifact-free the
// same way. It intentionally overflows the nominal 16x16 icon slot slightly
// (there's real spacing margin between icons — see HM_CX in homeMenu()).
static const uint8_t gearIcon18x18_[] PROGMEM = {
  0x00, 0x00, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x98, 0x67, 0x00,
  0xF8, 0x7F, 0x00,
  0xF0, 0x3F, 0x00,
  0x70, 0x38, 0x00,
  0x38, 0x70, 0x00,
  0x3E, 0xF0, 0x01,
  0x3E, 0xF0, 0x01,
  0x38, 0x70, 0x00,
  0x70, 0x38, 0x00,
  0xF0, 0x3F, 0x00,
  0xF8, 0x7F, 0x00,
  0x98, 0x67, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x03, 0x00,
  0x00, 0x00, 0x00,
};

void Display::drawSettingsIcon_(uint8_t x, uint8_t y, bool inv) {
  u8g2_.setDrawColor(inv ? 0 : 1);
  // Real bug this fixes: drawXBMP is NOT transparent by default — its "0"
  // bits paint the opposite color across the whole bounding box
  // (u8g2_DrawHXBMP checks u8g2->bitmap_transparency, off unless set),
  // which was wiping the corners of the round selection-highlight disc
  // homeMenu() draws behind a selected icon, squaring it off. Transparency
  // makes "0" bits leave whatever's already there alone, like every other
  // icon-drawing function here already behaves.
  u8g2_.setBitmapMode(1);
  // Centered on the same point the 16x16 slot's own center sits at
  // (x+7.5, y+7.5), plus the same 1px-further-left bias asked for earlier.
  u8g2_.drawXBMP(x - 2, y - 1, 18, 18, gearIcon18x18_);
  u8g2_.setDrawColor(1);
}

// Power button: circle ring with a gap at top and a vertical stem through the
// gap. The ring is drawn as a filled disc with a smaller disc punched out of
// its center (a clean annulus) rather than a 1px circle outline — reliably
// thicker than doubling up two adjacent outline circles, which risks
// leaving pinhole gaps at small radii.
void Display::drawPowerIcon_(uint8_t x, uint8_t y, bool inv) {
  u8g2_.setDrawColor(inv ? 0 : 1);
  u8g2_.drawDisc(x + 7, y + 7, 6);        // outer edge — a tiny bit smaller
  u8g2_.setDrawColor(inv ? 1 : 0);
  u8g2_.drawDisc(x + 7, y + 7, 5);        // punch the center — same ring thickness
  u8g2_.drawBox(x + 5, y + 1, 5, 3);      // punch the gap at the top for the stem
  u8g2_.setDrawColor(inv ? 0 : 1);
  u8g2_.drawVLine(x + 7, y, 5);           // stem — 1px wide
  u8g2_.setDrawColor(1);
}

// Battery: rounded-rect body, upright (taller than wide) with a small
// terminal nub on top, and an inner fill drawn from the bottom up in 4
// discrete levels (quarter/half/three-quarter/full) rather than a smooth
// proportional bar — matches the tiered 25/50/75/100 states asked for.
void Display::drawBatteryIcon_(uint8_t x, uint8_t y, uint8_t pct, bool inv) {
  u8g2_.setDrawColor(inv ? 0 : 1);
  const uint8_t bx = x + 3, by = y + 3, bw = 9, bh = 12;
  u8g2_.drawRFrame(bx, by, bw, bh, 1);
  u8g2_.drawBox(bx + 2, by - 2, 5, 2);   // terminal nub, on top

  // 1=quarter, 2=half, 3=three-quarter (75-90), 4=full (91-100).
  uint8_t level = (pct <= 25) ? 1 : (pct <= 50) ? 2 : (pct <= 90) ? 3 : 4;
  const uint8_t innerX = bx + 1, innerY = by + 1, innerW = bw - 2, innerH = bh - 2;
  uint8_t fillH = (uint8_t)((uint16_t)innerH * level / 4);
  if (fillH > 0) {
    u8g2_.drawBox(innerX, innerY + (innerH - fillH), innerW, fillH);
  }
  u8g2_.setDrawColor(1);
}

void Display::homeMenu(uint8_t selected, const char *coinTicker, const char *label,
                       bool bleOn, bool bleConnected, bool usbConn, uint8_t batteryPct,
                       bool showCoinArrows) {
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);

  // Connection indicator — top-right corner, 4x6 font. "BT" is shown
  // whenever Bluetooth is on, not only once a device is actually
  // connected - so it's always visible as a standing radio-state
  // indicator, not just a "currently paired" one; once a device actually
  // connects it becomes "-BT-" to distinguish the two states. Right-aligned
  // by measured width rather than a hardcoded x per string, so the longer
  // "-BT-"/"USB" strings don't need their own hand-picked offsets.
  if (bleOn || usbConn) {
    u8g2_.setFont(font4x6_());
    const char *txt = bleOn ? (bleConnected ? "-BT-" : "BT") : "USB";
    uint8_t w = u8g2_.getUTF8Width(txt);
    u8g2_.drawUTF8(OLED_WIDTH - 2 - w, 6, txt);
  }

  for (uint8_t i = 0; i < 5; i++) {
    uint8_t ix  = HM_CX[i] - 8;   // left edge of 16×16 icon slot
    bool    sel = (i == selected);

    if (sel) {
      // Solid white disc behind the selected icon; icon is then drawn in black.
      u8g2_.setDrawColor(1);
      u8g2_.drawDisc(ix + 7, HM_ICON_TOP + 7, 9);
    }

    switch (i) {
      case 0: drawCoinIcon_   (ix, HM_ICON_TOP, coinTicker, sel); break;
      case 1: drawLockIcon_   (ix, HM_ICON_TOP, sel); break;
      case 2: drawSettingsIcon_(ix, HM_ICON_TOP, sel); break;
      case 3: drawBatteryIcon_(ix, HM_ICON_TOP, batteryPct, sel); break;
      case 4: drawPowerIcon_  (ix, HM_ICON_TOP, sel); break;
    }

    // Up/down arrow hints on the coin slot — always white, outside the disc.
    // Hidden when there's nothing to cycle to (showCoinArrows false).
    if (i == 0 && showCoinArrows) {
      u8g2_.setDrawColor(1);
      // Up arrow gap: 2px -> 4px (equalized with down) -> 5px (this pass).
      // Down arrow gap: 3px -> 4px (equalized with up).
      u8g2_.drawPixel(ix + 7, HM_ICON_TOP - 8);       // up arrow tip
      u8g2_.drawHLine(ix + 6, HM_ICON_TOP - 7, 3);
      u8g2_.drawHLine(ix + 5, HM_ICON_TOP - 6, 5);    // up arrow base
      u8g2_.drawHLine(ix + 5, HM_ICON_TOP + 20, 5);   // down arrow base
      u8g2_.drawHLine(ix + 6, HM_ICON_TOP + 21, 3);
      u8g2_.drawPixel(ix + 7, HM_ICON_TOP + 22);      // down arrow tip
    }
  }

  // Left/right nav arrows at screen edges, vertically centred on the icon row.
  {
    uint8_t cy = HM_ICON_TOP + 7;   // vertical centre of icon row
    u8g2_.setDrawColor(1);
    // Left arrow (← tip at x=0) — mirrors up/down pattern: VLine per column
    u8g2_.drawVLine(2, cy - 2, 5);   // base column: 5 px tall
    u8g2_.drawVLine(1, cy - 1, 3);   // middle column: 3 px tall
    u8g2_.drawPixel(0, cy);           // tip
    // Right arrow (→ tip at x=127)
    u8g2_.drawVLine(125, cy - 2, 5); // base column: 5 px tall
    u8g2_.drawVLine(126, cy - 1, 3); // middle column: 3 px tall
    u8g2_.drawPixel(127, cy);         // tip
  }

  u8g2_.setFont(font7x13B_());
  uint8_t lw = u8g2_.getUTF8Width(label);
  u8g2_.drawUTF8((OLED_WIDTH - lw) / 2, HM_LABEL_Y, label);

  u8g2_.sendBuffer();
}

void Display::splash(const char *title, const char *subtitle) {
  u8g2_.clearBuffer();
  u8g2_.setFont(u8g2_font_ncenB10_tr);
  int tw = u8g2_.getUTF8Width(title);
  int ty;
  if (subtitle && subtitle[0]) {
    ty = 30;   // two-line layout, title pinned above the subtitle
  } else {
    // No subtitle - vertically center the title on the whole panel using
    // real font metrics (ascent/descent), not a hardcoded y.
    int asc  = u8g2_.getAscent();
    int desc = u8g2_.getDescent();   // negative
    ty = (OLED_HEIGHT - (asc - desc)) / 2 + asc;
  }
  u8g2_.drawUTF8((OLED_WIDTH - tw) / 2, ty, title);
  if (subtitle && subtitle[0]) {
    u8g2_.setFont(font6x12_());
    int sw = u8g2_.getUTF8Width(subtitle);
    u8g2_.drawUTF8((OLED_WIDTH - sw) / 2, 48, subtitle);
  }
  u8g2_.sendBuffer();
}

void Display::menu(const char *title, const char *const *items, uint8_t count, uint8_t selected,
                    uint8_t activeIndex) {
  u8g2_.clearBuffer();
  drawTitleBar_(title);

  // Compute a scroll window that keeps `selected` visible.
  uint8_t first = 0;
  if (count > MENU_ROWS) {
    if (selected >= MENU_ROWS - 1) first = selected - (MENU_ROWS - 1);
    if (first > count - MENU_ROWS) first = count - MENU_ROWS;
  }

  u8g2_.setFont(font6x12_());
  for (uint8_t row = 0; row < MENU_ROWS && (first + row) < count; row++) {
    uint8_t idx = first + row;
    int y = BODY_TOP + row * LINE_H;
    u8g2_.drawUTF8(0, y, (idx == selected) ? ">" : " ");
    u8g2_.drawUTF8(10, y, items[idx]);
    if (idx == activeIndex) {
      drawCheckmark_(OLED_WIDTH - 14, y - 9);
    }
  }
  u8g2_.sendBuffer();
}

// Short down-stroke then longer up-stroke, like a hand-drawn tick — the
// 6x12 font has no checkmark glyph (ASCII-only), so this is drawn with
// plain line primitives instead of relying on font coverage.
void Display::drawCheckmark_(uint8_t x, uint8_t y) {
  u8g2_.drawLine(x, y + 4, x + 2, y + 6);
  u8g2_.drawLine(x + 2, y + 6, x + 7, y + 1);
}

void Display::drawToggle_(uint8_t x, uint8_t y, float pos) {
  if (pos < 0.0f) pos = 0.0f;
  if (pos > 1.0f) pos = 1.0f;
  const uint8_t trackW = 20, trackH = 10, knobD = 8;
  u8g2_.drawRFrame(x, y, trackW, trackH, trackH / 2);
  int cx0 = x + knobD / 2;
  int cx1 = x + trackW - 1 - knobD / 2;
  int cx  = cx0 + (int)((cx1 - cx0) * pos + 0.5f);
  u8g2_.drawDisc(cx, y + trackH / 2, knobD / 2);
}

void Display::settingsMenu(const char *title, const SettingsRow *rows, uint8_t count,
                            uint8_t selected, float animKnobPos) {
  u8g2_.clearBuffer();
  drawTitleBar_(title);

  // Compute a scroll window that keeps `selected` visible — same windowing
  // as menu(), needed now that Settings has more rows than fit on screen.
  uint8_t first = 0;
  if (count > MENU_ROWS) {
    if (selected >= MENU_ROWS - 1) first = selected - (MENU_ROWS - 1);
    if (first > count - MENU_ROWS) first = count - MENU_ROWS;
  }

  u8g2_.setFont(font6x12_());
  for (uint8_t row = 0; row < MENU_ROWS && (first + row) < count; row++) {
    uint8_t idx = first + row;
    int y = BODY_TOP + row * LINE_H;
    u8g2_.drawUTF8(0, y, (idx == selected) ? ">" : " ");
    u8g2_.drawUTF8(10, y, rows[idx].label);
    if (rows[idx].isToggle) {
      float pos = rows[idx].on ? 1.0f : 0.0f;
      if (idx == selected && animKnobPos >= 0.0f) pos = animKnobPos;
      drawToggle_(OLED_WIDTH - 22, y - 9, pos);
    }
  }
  u8g2_.sendBuffer();
}

void Display::pinEntry(const char *title, const char *stars, uint8_t curPos, bool canConfirm) {
  // Digits 0-9 at 10 px step (3 px gap between 7-px glyphs); OK circle follows.
  // curPos 0-9 = digit, curPos 10 = OK circle.
  static const uint8_t DX[10] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
  const uint8_t OK_CX  = 114;  // OK circle centre x
  const uint8_t OK_CY  = 31;   // OK circle centre y
  const uint8_t OK_R   = 7;    // OK circle radius
  const uint8_t DIG_BL = 36;   // 7x13B baseline (digit visible ≈ y=26..36)
  const uint8_t UL_Y   = 38;   // underline y: 2 px below digit baseline

  u8g2_.clearBuffer();
  drawTitleBar_(title);
  u8g2_.setDrawColor(1);
  u8g2_.setFont(font7x13B_());

  // Digits 0-9
  for (uint8_t d = 0; d < 10; d++) {
    char dstr[2] = { (char)('0' + d), '\0' };
    u8g2_.drawUTF8(DX[d] - 3, DIG_BL, dstr);
  }

  // Underline beneath selected digit (not drawn when OK circle is selected)
  if (curPos <= 9)
    u8g2_.drawHLine(DX[curPos] - 4, UL_Y, 8);

  // OK circle — filled when enough digits committed, outline otherwise.
  // OK circle — fills only when the user navigates to it (curPos == 10).
  u8g2_.setFont(font4x6_());
  if (curPos == 10) {
    u8g2_.drawDisc(OK_CX, OK_CY, OK_R);
    u8g2_.setDrawColor(0);
    u8g2_.drawUTF8(OK_CX - 3, OK_CY + 3, "OK");
    u8g2_.setDrawColor(1);
  } else {
    u8g2_.drawCircle(OK_CX, OK_CY, OK_R);
    u8g2_.drawUTF8(OK_CX - 3, OK_CY + 3, "OK");
  }


  // Stars: 8 fixed slots at y=55; filled disc = committed, single pixel = empty
  static const uint8_t SX[8] = { 16, 30, 44, 58, 72, 86, 100, 114 };
  size_t n = strlen(stars);
  for (uint8_t i = 0; i < 8; i++) {
    if (i < n) u8g2_.drawDisc(SX[i], 55, 2);
    else        u8g2_.drawPixel(SX[i], 55);
  }

  u8g2_.sendBuffer();
}

void Display::message(const char *title, const char *body, bool centered) {
  u8g2_.clearBuffer();
  drawTitleBar_(title);
  u8g2_.setFont(font6x12_());

  int y = BODY_TOP;
  if (centered) {
    // Vertically center the whole body block within the space BELOW the
    // title bar (TITLE_H..OLED_HEIGHT) - the title bar's own height is
    // excluded from this calculation, not treated as part of the area
    // being centered within.
    int lineCount = 0;
    if (body && *body) {
      lineCount = 1;
      for (const char *q = body; *q; q++) if (*q == '\n') lineCount++;
    }
    int blockH = lineCount * LINE_H;
    int availH = OLED_HEIGHT - TITLE_H;
    int topPad = (availH - blockH) / 2;
    if (topPad < 0) topPad = 0;
    y = TITLE_H + topPad + LINE_H;   // first line's baseline
  }
  const char *p = body ? body : "";
  char line[32];
  while (p && *p) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len >= sizeof(line)) len = sizeof(line) - 1;
    memcpy(line, p, len);
    line[len] = '\0';
    int x = 0;
    if (centered) {
      int w = u8g2_.getUTF8Width(line);
      x = (OLED_WIDTH - w) / 2;
      if (x < 0) x = 0;
    }
    u8g2_.drawUTF8(x, y, line);
    y += LINE_H;
    if (y > OLED_HEIGHT) break;
    if (!nl) break;
    p = nl + 1;
  }
  u8g2_.sendBuffer();
}

void Display::importantPage(const char *title, const char *body, bool showPrev, bool showNext) {
  u8g2_.setFont(font6x12_());

  // Measure the widest line first (cheap - getStrWidth only, no drawing)
  // so the arrows can be pushed outward, past a fixed edge margin, on any
  // page whose text is wide enough to otherwise collide with them.
  int maxLineW = 0;
  {
    const char *p = body ? body : "";
    char line[32];
    while (p && *p) {
      const char *nl = strchr(p, '\n');
      size_t len = nl ? (size_t)(nl - p) : strlen(p);
      if (len >= sizeof(line)) len = sizeof(line) - 1;
      memcpy(line, p, len);
      line[len] = '\0';
      int w = u8g2_.getUTF8Width(line);
      if (w > maxLineW) maxLineW = w;
      if (!nl) break;
      p = nl + 1;
    }
  }

  message(title, body, /*centered=*/true);   // draws + sends the buffer once...

  // ...then draw the arrows on top and send again. u8g2's buffer still
  // holds the just-drawn frame at this point (clearBuffer() only runs at
  // the top of the next draw call), so this is a cheap two-step rather
  // than duplicating message()'s whole centered-body layout logic here.
  int availH = OLED_HEIGHT - TITLE_H;
  int cy = TITLE_H + availH / 2;
  const int aw = 6, ah = 8, margin = 6, gap = 4;
  int textLeft  = (OLED_WIDTH - maxLineW) / 2;
  int textRight = textLeft + maxLineW;
  if (showPrev) {
    int ax = margin;
    int wantedAx = textLeft - gap - aw;   // outside the text, with a real gap
    if (wantedAx < ax) ax = wantedAx;     // text is wide - push the arrow further left
    if (ax < 0) ax = 0;                   // never off-screen
    u8g2_.drawTriangle(ax + aw, cy - ah / 2, ax + aw, cy + ah / 2, ax, cy);
  }
  if (showNext) {
    int ax = OLED_WIDTH - margin - aw;
    int wantedAx = textRight + gap;
    if (wantedAx > ax) ax = wantedAx;     // text is wide - push the arrow further right
    if (ax + aw > OLED_WIDTH) ax = OLED_WIDTH - aw;
    u8g2_.drawTriangle(ax, cy - ah / 2, ax, cy + ah / 2, ax + aw, cy);
  }
  u8g2_.sendBuffer();
}

void Display::wordEntryPage(const char *title, const char *typedLine, const char *matchLine,
                             const char *hint) {
  u8g2_.clearBuffer();
  drawTitleBar_(title);

  // Typed prefix + cursor letter: bold and a bit larger, same font
  // seedWordPage() uses for its own word - this screen is about typing a
  // word too, so it should look and feel like the same "big word" family
  // rather than plain body text.
  u8g2_.setFont(font7x13B_());
  int y1 = TITLE_H + 14;
  u8g2_.drawUTF8(2, y1, typedLine);

  // Small stacked Up/Down arrows at the right edge, vertically centered on
  // the typed line's own row - shows Up/Down cycles the current letter
  // without spelling it out in text.
  {
    // Hand-built row-by-row (not u8g2's own drawTriangle()) so the up and
    // down shapes are pixel-identical mirrors by construction - at this
    // tiny size, drawTriangle() itself rasterized the two orientations
    // asymmetrically (the downward one came out visibly larger/clipped).
    int cx = OLED_WIDTH - 10;
    int cy = y1 - 5;   // roughly the typed line's vertical center
    const int halfW = 3, h = 4, gap = 2;
    for (int dir = -1; dir <= 1; dir += 2) {
      for (int i = 0; i < h; i++) {
        int w = (halfW * (h - 1 - i)) / (h - 1);   // halfW at base, 0 at apex tip
        int y = cy + dir * (gap + i);
        u8g2_.drawHLine(cx - w, y, 2 * w + 1);
      }
    }
  }

  // Live top-matching candidate word (or "No match"): smaller, plain,
  // directly below - clearly secondary to what's actually being typed.
  u8g2_.setFont(font6x12_());
  int y2 = y1 + 16;
  u8g2_.drawUTF8(2, y2, matchLine);

  // Button instructions: one short line only, small font, centered, pinned
  // near the bottom - only the action that actually differs frame-to-frame
  // (whether Hold=pick is available), not a full recap of every button.
  u8g2_.setFont(font5x7_());
  int hw = u8g2_.getUTF8Width(hint);
  int hx = (OLED_WIDTH - hw) / 2;
  if (hx < 0) hx = 0;
  u8g2_.drawUTF8(hx, OLED_HEIGHT - 1, hint);

  u8g2_.sendBuffer();
}

void Display::seedWordPage(const char *title, const char *word, bool showPrev, bool showNext,
                            bool showDoneHint) {
  u8g2_.clearBuffer();
  drawTitleBar_(title);

  // Word itself: bold, larger than the plain 6x12 body font, vertically +
  // horizontally centered in the space below the title bar only.
  u8g2_.setFont(font7x13B_());
  int ww = u8g2_.getUTF8Width(word);
  int wx = (OLED_WIDTH - ww) / 2;
  if (wx < 0) wx = 0;
  int fontH = u8g2_.getAscent() - u8g2_.getDescent();
  int availH = OLED_HEIGHT - TITLE_H;
  int wy = TITLE_H + (availH - fontH) / 2 + u8g2_.getAscent();
  u8g2_.drawUTF8(wx, wy, word);

  // Prev/Next as small triangle arrows pinned near the screen's own left
  // and right edges, pushed further out (never closer to center) whenever
  // the word itself is wide enough to otherwise collide with them - same
  // adaptive-gap approach as importantPage(), same drawTriangle()
  // primitive used for the home menu's up/down coin-cycle hints elsewhere
  // in this file.
  u8g2_.setFont(font6x12_());
  int cy = TITLE_H + availH / 2;   // vertical center of the word's own row
  const int aw = 6, ah = 8, margin = 6, gap = 4;
  if (showPrev) {
    int ax = margin;
    int wantedAx = wx - gap - aw;
    if (wantedAx < ax) ax = wantedAx;
    if (ax < 0) ax = 0;
    u8g2_.drawTriangle(ax + aw, cy - ah / 2, ax + aw, cy + ah / 2, ax, cy);
  }
  if (showNext) {
    int ax = OLED_WIDTH - margin - aw;
    int wantedAx = wx + ww + gap;
    if (wantedAx > ax) ax = wantedAx;
    if (ax + aw > OLED_WIDTH) ax = OLED_WIDTH - aw;
    u8g2_.drawTriangle(ax, cy - ah / 2, ax, cy + ah / 2, ax + aw, cy);
  }

  if (showDoneHint) {
    const char *hint = "Hold OK to continue";
    int hw = u8g2_.getUTF8Width(hint);
    int hx = (OLED_WIDTH - hw) / 2;
    if (hx < 0) hx = 0;
    u8g2_.drawUTF8(hx, OLED_HEIGHT - 1, hint);
  }

  u8g2_.sendBuffer();
}

void Display::coinPrompt(const char *ticker, const char *title, const char *body,
                          const char *hint, bool iconHint) {
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);

  const uint8_t iconX = (OLED_WIDTH - 16) / 2;
  drawCoinIcon_(iconX, 2, ticker, false);

  u8g2_.setFont(font6x12_());
  auto centerLine = [&](const char *s, int y) {
    if (!s || !*s) return;
    int w = u8g2_.getUTF8Width(s);
    int x = (OLED_WIDTH - w) / 2;
    if (x < 0) x = 0;
    u8g2_.drawUTF8(x, y, s);
  };

  centerLine(title, 34);
  centerLine(body,  46);

  if (iconHint) {
    // Back-arrow (cancel) bottom-left, OK checkmark bottom-right - replaces
    // the old "SEL=open/BK=cancel" text hint for the sign-select prompt.
    drawBackArrowIcon_(6, OLED_HEIGHT - 14);
    drawCheckmark_(OLED_WIDTH - 18, OLED_HEIGHT - 14);
  } else if (hint && *hint) {
    // hint may itself be two lines ("SEL=open\nBK=cancel"); split and pin
    // both near the bottom.
    const char *nl = strchr(hint, '\n');
    if (nl) {
      char first[24];
      size_t len = (size_t)(nl - hint);
      if (len >= sizeof(first)) len = sizeof(first) - 1;
      memcpy(first, hint, len);
      first[len] = '\0';
      centerLine(first, 56);
      centerLine(nl + 1, 64);
    } else {
      centerLine(hint, 62);
    }
  }

  u8g2_.sendBuffer();
}

void Display::drawBackArrowIcon_(uint8_t x, uint8_t y) {
  u8g2_.drawLine(x + 7, y,     x,     y + 5);
  u8g2_.drawLine(x,     y + 5, x + 7, y + 10);
}

void Display::coinReady(const char *ticker, const char *body) {
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);

  const uint8_t iconX = (OLED_WIDTH - 16) / 2;
  drawCoinIcon_(iconX, 4, ticker, false);

  u8g2_.setFont(font6x12_());
  if (body && *body) {
    int w = u8g2_.getUTF8Width(body);
    int x = (OLED_WIDTH - w) / 2;
    if (x < 0) x = 0;
    u8g2_.drawUTF8(x, 40, body);
  }

  // Down-arrow hint pinned near the bottom - press DOWN for Receive/Settings.
  u8g2_.drawTriangle(60, 57, 68, 57, 64, 63);

  u8g2_.sendBuffer();
}

void Display::arrowMenu(const char *const *items, uint8_t count, uint8_t selected) {
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);

  // Up-arrow hint at the top - press UP to return to the coin-ready screen.
  u8g2_.drawTriangle(60, 6, 68, 6, 64, 0);

  u8g2_.setFont(font6x12_());
  int y = 32;
  for (uint8_t i = 0; i < count; i++) {
    char line[24];
    snprintf(line, sizeof(line), "%s %s", (i == selected) ? ">" : " ", items[i]);
    u8g2_.drawUTF8(12, y, line);
    y += LINE_H;
  }

  u8g2_.sendBuffer();
}

void Display::centeredMessage(const char *body) {
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);
  u8g2_.setFont(font6x12_());

  // No title bar. Every '\n'-separated line is horizontally centered, and
  // the whole block is vertically centered on the 64px panel — unlike
  // message()'s left-aligned, title-bar-anchored layout, this is for a
  // screen that's just standalone centered text (e.g. About).
  const char *body_ = body ? body : "";
  int lineCount = 1;
  for (const char *q = body_; *q; q++) {
    if (*q == '\n') lineCount++;
  }
  int top = (OLED_HEIGHT - lineCount * LINE_H) / 2;
  if (top < 0) top = 0;

  int y = top + LINE_H;
  const char *p = body_;
  char line[32];
  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len >= sizeof(line)) len = sizeof(line) - 1;
    memcpy(line, p, len);
    line[len] = '\0';
    int w = u8g2_.getUTF8Width(line);
    int x = (OLED_WIDTH - w) / 2;
    if (x < 0) x = 0;
    u8g2_.drawUTF8(x, y, line);
    y += LINE_H;
    if (y > OLED_HEIGHT) break;
    if (!nl) break;
    p = nl + 1;
  }
  u8g2_.sendBuffer();
}

void Display::loading(const char *message, uint8_t pct) {
  if (pct > 100) pct = 100;
  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);

  // No title bar — just the centered message, always split across exactly
  // 2 lines (never a single-line shortcut) so every coin gets the exact
  // same layout. Real bug this fixes: font size was already identical in
  // every case (confirmed live via serial — every draw used the same
  // u8g2_font_6x12_tr, no font ever changed), but a short name like "dYdX"
  // or "Axelar" fit on one centered line with a lot of surrounding empty
  // space, while longer names ("Bitcoin", "Cosmos Hub", ...) wrapped to 2
  // tighter lines — the lone, spacious single line reads as noticeably more
  // prominent than a cramped 2-line pair even though the glyphs are
  // pixel-identical. Always wrapping removes the inconsistency at the root.
  if (message && message[0]) {
    u8g2_.setFont(font6x12_());
    // Greedy word-wrap onto exactly 2 lines: walk each space left to right,
    // remembering the last one whose prefix still fits — the widest first
    // line that still fits, whatever's left goes on line 2. For a message
    // that already fits on one line, this naturally puts just the final
    // word (always "Network") on line 2.
    char buf[40];
    snprintf(buf, sizeof(buf), "%s", message);
    char *lastSpace = nullptr;
    for (char *sp = strchr(buf, ' '); sp; sp = strchr(sp + 1, ' ')) {
      char saved = *sp;
      *sp = '\0';
      int w = u8g2_.getUTF8Width(buf);
      *sp = saved;
      if (w <= OLED_WIDTH) {
        lastSpace = sp;
      } else {
        break;
      }
    }
    const char *line2 = "";
    if (lastSpace) {
      *lastSpace = '\0';
      line2 = lastSpace + 1;
    }
    int w1 = u8g2_.getUTF8Width(buf);
    int x1 = (OLED_WIDTH - w1) / 2;
    if (x1 < 0) x1 = 0;
    u8g2_.drawUTF8(x1, 16, buf);
    if (line2[0]) {
      int w2 = u8g2_.getUTF8Width(line2);
      int x2 = (OLED_WIDTH - w2) / 2;
      if (x2 < 0) x2 = 0;
      u8g2_.drawUTF8(x2, 30, line2);
    }
  }

  // Rounded "pill" progress bar with the "NN%" readout centred inside it.
  // The readout is drawn twice through two clip windows (the filled
  // segment, then the empty track) so it stays legible — inverted color
  // over the solid fill, normal color over the empty track — regardless
  // of where the fill edge currently sits.
  const int barW = 88, barH = 16;
  const int barX = (OLED_WIDTH - barW) / 2;
  const int barY = 40;
  const int r    = barH / 2;
  u8g2_.setDrawColor(1);
  u8g2_.drawRFrame(barX, barY, barW, barH, r);
  int fillW = (int)((barW - 4) * (uint32_t)pct / 100);
  if (fillW > 0) {
    // Real bug found here: u8g2_DrawRBox's internal height math is
    // `hh = h; hh -= r; hh -= r;` on an UNSIGNED coordinate type — if r is
    // more than half of h, that underflows to a huge value and the library
    // draws a box with a wraparound-enormous height (looked like a
    // full-screen-tall bar). The fill box is barH-4 tall, not barH, so its
    // radius must be capped against *that* height, not the outer bar's r.
    const int innerH = barH - 4;
    int fillR = fillW / 2;
    if (fillR > innerH / 2) fillR = innerH / 2;
    u8g2_.drawRBox(barX + 2, barY + 2, fillW, innerH, fillR);
  }

  char pctStr[6];
  snprintf(pctStr, sizeof(pctStr), "%u%%", pct);
  u8g2_.setFont(font5x7_());
  int pw = u8g2_.getUTF8Width(pctStr);
  int px = barX + (barW - pw) / 2;
  int py = barY + barH / 2 + 3;   // baseline offset for a 5x7 font, vertically centred
  int fillEdge = barX + 2 + fillW;

  u8g2_.setClipWindow(barX, barY, fillEdge, barY + barH);
  u8g2_.setDrawColor(0);
  u8g2_.drawUTF8(px, py, pctStr);
  u8g2_.setMaxClipWindow();

  u8g2_.setClipWindow(fillEdge, barY, barX + barW, barY + barH);
  u8g2_.setDrawColor(1);
  u8g2_.drawUTF8(px, py, pctStr);
  u8g2_.setMaxClipWindow();
  u8g2_.setDrawColor(1);

  u8g2_.sendBuffer();
}

void Display::qr(const char *text) {
  // IMPORTANT: the QRCode library does NOT bounds-check data vs. version — it
  // overflows an internal buffer if the data is too big for the chosen version.
  // We must pick the correct minimum version BEFORE calling the encoder.
  //
  // Capacity tables at ECC_L, indexed by version 1..12.
  static const uint16_t CAP_BYTE_L[]  = { 0, 17, 32,  53,  78, 106, 134, 154, 192, 230, 271, 321, 367 };
  static const uint16_t CAP_ALPHA_L[] = { 0, 25, 47,  77, 114, 154, 195, 224, 279, 335, 395, 468, 535 };
  const uint8_t MAX_VER = 12;

  // Persistent storage — qrcode_initText is expensive; cache so re-renders are instant.
  static uint8_t buf[640];        // >= qrcode_getBufferSize(12) = 529; modules live here
  static QRCode  q;
  static char    cachedText[128] = "";

  if (strcmp(text, cachedText) != 0) {
    // New address — (re)encode.
    bool useAlpha = true;
    for (const char *p = text; *p; p++) {
      char c = *p;
      if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
            c == ' ' || c == '$' || c == '%' || c == '*' ||
            c == '+' || c == '-' || c == '.' || c == '/' || c == ':')) {
        useAlpha = false; break;
      }
    }
    const uint16_t *cap = useAlpha ? CAP_ALPHA_L : CAP_BYTE_L;

    size_t dlen = strlen(text);
    uint8_t ver = 0;
    for (uint8_t v = 1; v <= MAX_VER; v++) {
      if (cap[v] >= dlen) { ver = v; break; }
    }

    if (ver == 0) {
      u8g2_.clearBuffer(); drawTitleBar_("QR too big"); u8g2_.sendBuffer(); return;
    }
    if (qrcode_initText(&q, buf, ver, ECC_LOW, text) != 0) {
      u8g2_.clearBuffer(); drawTitleBar_("QR error");   u8g2_.sendBuffer(); return;
    }
    strncpy(cachedText, text, sizeof(cachedText) - 1);
    cachedText[sizeof(cachedText) - 1] = '\0';
  }

  // Render (fast — just pixel drawing from the cached module buffer).
  //
  // Always fills the full panel height (OLED_HEIGHT), regardless of module
  // count: a plain integer scale (floor(OLED_HEIGHT/total)) rounds DOWN to
  // 1 once an address is long enough to need more modules than fit at
  // scale 2 (e.g. SUI/APT/NEAR's 64-66 char hex addresses, ADA's ~103-char
  // bech32 address, BCH's CashAddr) — at scale 1 the QR is only `total`
  // pixels square, well under the 64px panel, instead of filling it. Fixed
  // by mapping each module to a float-computed column/row boundary
  // (moduleScale = OLED_HEIGHT/total as a float) instead of a fixed
  // integer box per module — most modules render at 1px, some at 2px, but
  // the columns/rows always sum to exactly OLED_HEIGHT, so the QR is
  // always full height no matter the address length.
  const uint8_t quiet = 1;
  uint16_t total = q.size + 2 * quiet;
  float moduleScale = (float)OLED_HEIGHT / (float)total;
  uint16_t dim = OLED_HEIGHT;
  int ox = (OLED_WIDTH - dim) / 2;
  int oy = 0;

  u8g2_.clearBuffer();
  u8g2_.setDrawColor(1);
  u8g2_.drawBox(ox, oy, dim, dim);
  u8g2_.setDrawColor(0);
  for (uint8_t y = 0; y < q.size; y++) {
    int py0 = (int)((quiet + y) * moduleScale + 0.5f);
    int py1 = (int)((quiet + y + 1) * moduleScale + 0.5f);
    for (uint8_t x = 0; x < q.size; x++) {
      if (qrcode_getModule(&q, x, y)) {
        int px0 = (int)((quiet + x) * moduleScale + 0.5f);
        int px1 = (int)((quiet + x + 1) * moduleScale + 0.5f);
        u8g2_.drawBox(ox + px0, oy + py0, px1 - px0, py1 - py0);
      }
    }
  }
  u8g2_.setDrawColor(1);
  u8g2_.sendBuffer();
}
