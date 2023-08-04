
#include "rng.h"
#include "sha256.h"
#include <string.h>

/* RNG state */
static uint8_t state[SHA256_DIGEST_SIZE];
static uint64_t counter = 0;

// Function to initialize the RNG state with a given seed
void rng_init(const uint8_t* seed) {
    memcpy(state, seed, SHA256_DIGEST_SIZE);
    counter = 0;
}

// Function to generate random bytes using the RNG state
void rng_generate(uint8_t* buffer, size_t size) {
    uint8_t input[SHA256_DIGEST_SIZE + sizeof(uint64_t)];
    while (size > 0) {
        // Increment the counter
        counter++;

        // Prepare the input by concatenating the state and counter
        memcpy(input, state, SHA256_DIGEST_SIZE);
        memcpy(input + SHA256_DIGEST_SIZE, &counter, sizeof(uint64_t));

        // Hash the input to produce random bytes
        sha256(input, SHA256_DIGEST_SIZE + sizeof(uint64_t), buffer);

        // Update the buffer and size
        buffer += SHA256_DIGEST_SIZE;
        size -= (size > SHA256_DIGEST_SIZE) ? SHA256_DIGEST_SIZE : size;
    }
}

// Function to reseed the RNG state with a new seed
void rng_reseed(const uint8_t* seed) {
    sha256(seed, SHA256_DIGEST_SIZE, state);
}
