#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
// Function prototypes
void rng_init(const uint8_t* seed);
void rng_generate(uint8_t* buffer, size_t size);
void rng_reseed(const uint8_t* seed);

#endif // RNG_H
