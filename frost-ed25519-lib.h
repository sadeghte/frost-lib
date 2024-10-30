

#ifndef FROST_ED25519_LIB_H
#define FROST_ED25519_LIB_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

const uint8_t *keys_generate_with_dealer(uint16_t min_signers, uint16_t max_signers);

void mem_free(const uint8_t *ptr, uintptr_t len);

#endif  /* FROST_ED25519_LIB_H */
