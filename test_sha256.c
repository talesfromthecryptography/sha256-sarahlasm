#include "sha256.h"
#include <string.h>
#include <stdio.h>

void hash(uint32_t result[], uint8_t dataToRead[], uint8_t length) {
  sha256_state state;
  sha256_init(&state);
  sha256_update(&state, dataToRead, length);
  sha256_final(&state, result);
}

int main() {

  uint32_t result[32];
  uint8_t dataToRead[] = {'s', 'a', 'r', 'a', 'h'};
  hash(result, dataToRead, 5);

  printf("Result:\t\t");
  printData(result);
  printf("Should be:\td233633d9524e84c71d6fe45eb3836f8919148e4a5fc2234cc9e6494ec0f11c2\n");

  uint32_t result2[32];
  uint8_t dataToRead2[] = {'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c', 'c', 'c'}; //That's 65 c's if you don't want to count
  hash(result2, dataToRead2, 65);

  printf("\nResult:\t\t");
  printData(result2);
  printf("Should be:\tb30855e510446ac34706c5acafeedefd5122fe9446b3f812db11e1ac3b4d0cf2\n");

  uint32_t result3[32];
  uint8_t dataToRead3[] = {'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
     'c', 'c', 'c'}; //That's 63 c's if you don't want to count
  hash(result3, dataToRead3, 63);

  printf("\nResult:\t\t");
  printData(result3);
  printf("Should be:\t93378fdea13e1d912d953fedf1155adf0c184626216bf333f9b4f50b704bff63\n");
}
