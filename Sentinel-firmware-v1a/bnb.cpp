#include "bnb.h"
#include "eth.h"

namespace bnb {

String address(const uint8_t *entropy, size_t entLen,
               const char *passphrase, uint32_t index) {
  return eth::address(entropy, entLen, passphrase, index);
}

}  // namespace bnb
