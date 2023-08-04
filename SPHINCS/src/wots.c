
#include "wots.h"
#include <string.h>
#include "rng.h"

// Constants for error codes
// Constants for error codes
#define WOTS_SUCCESS 0
#define WOTS_NULL_POINTER -1
#define WOTS_INVALID_BUFFER_SIZE -2
#define WOTS_INVALID_SIGNATURE -3


// Function to convert a hash to base W
static void convert_to_base_w(const uint8_t* hash, uint8_t* base_w) {
    int sum = 0;
    for (int i = 0; i < WOTS_LEN - 1; ++i) {
        base_w[i] = (hash[i / 2] >> (4 * (i % 2))) & (WOTS_W - 1);
        sum += base_w[i];
    }
    base_w[WOTS_LEN - 1] = (WOTS_W - 1) * (WOTS_LEN - 1) - sum;
}

// Constant-time comparison function
static int constant_time_compare(const uint8_t* a, const uint8_t* b, size_t size) {
    uint8_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void wots_generate_private_key(uint8_t* private_key) {
    rng_generate(private_key, WOTS_LEN * SHA256_DIGEST_SIZE);
}

static void chain(const uint8_t* start, int steps, uint8_t* result) {
    memcpy(result, start, SHA256_DIGEST_SIZE);
    for (int i = 0; i < steps; ++i) {
        sha256(result, SHA256_DIGEST_SIZE, result);
    }
}

void wots_generate_public_key(const uint8_t* private_key, uint8_t* public_key) {
    uint8_t tmp[WOTS_LEN * SHA256_DIGEST_SIZE];
    for (int i = 0; i < WOTS_LEN; ++i) {
        chain(private_key + i * SHA256_DIGEST_SIZE, WOTS_W - 1, tmp + i * SHA256_DIGEST_SIZE);
    }
    sha256(tmp, WOTS_LEN * SHA256_DIGEST_SIZE, public_key);
}

void wots_sign(const uint8_t* message, const uint8_t* private_key, uint8_t* signature) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t base_w[WOTS_LEN];
    sha256((const uint8_t*)message, strlen((const char*)message), hash);
    convert_to_base_w(hash, base_w);
    for (int i = 0; i < WOTS_LEN; ++i) {
        chain(private_key + i * SHA256_DIGEST_SIZE, base_w[i], signature + i * SHA256_DIGEST_SIZE);
    }
}

int wots_verify(const uint8_t* message, const uint8_t* signature, const uint8_t* public_key) {
    if (!message || !signature || !public_key) return WOTS_NULL_POINTER;
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t base_w[WOTS_LEN];
    uint8_t tmp[WOTS_LEN * SHA256_DIGEST_SIZE];
    uint8_t reconstructed_public_key[SHA256_DIGEST_SIZE];
    sha256(message, strlen((const char*)message), hash);
    convert_to_base_w(hash, base_w);
    for (int i = 0; i < WOTS_LEN; ++i) {
        chain(signature + i * SHA256_DIGEST_SIZE, WOTS_W - 1 - base_w[i], tmp + i * SHA256_DIGEST_SIZE);
    }
    sha256(tmp, WOTS_LEN * SHA256_DIGEST_SIZE, reconstructed_public_key);
    return constant_time_compare(reconstructed_public_key, public_key, SHA256_DIGEST_SIZE) ? WOTS_SUCCESS : WOTS_INVALID_SIGNATURE;
}
