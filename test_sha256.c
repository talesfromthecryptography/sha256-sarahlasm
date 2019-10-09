#include "sha256.h"
#include <string.h>
#include <stdio.h>



int main() {

  uint32_t data[SHA256_DIGEST_SIZE];
  sha256_state state;
  sha256_init(&state);
  uint32_t c;
  uint8_t dataToRead[] = {'s', 'a', 'r', 'a', 'h'};
  sha256_update(&state, dataToRead, 5);
  sha256_final(&state, data);

  printData(data);
}
