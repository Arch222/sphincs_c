#include "sha256.h"
#include <string.h>

#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 message schedule */
static void sha256_prepare_schedule(const uint8_t* data, uint32_t* schedule) {
    int i;
    for (i = 0; i < 16; ++i) {
        schedule[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }

    for (i = 16; i < 64; ++i) {
        uint32_t s0 = ROTRIGHT(schedule[i - 15], 7) ^ ROTRIGHT(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
        uint32_t s1 = ROTRIGHT(schedule[i - 2], 17) ^ ROTRIGHT(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }
}

/* SHA-256 transform function */
static void sha256_transform(const uint8_t* data, uint32_t* state) {
    /* SHA-256 message schedule */
    uint32_t schedule[64];
    sha256_prepare_schedule(data, schedule);

    /* Initialize working variables to current hash value */
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    /* SHA-256 compression function main loop */
    int i;
    for (i = 0; i < 64; ++i) {
        uint32_t S1 = ROTRIGHT(e, 6) ^ ROTRIGHT(e, 11) ^ ROTRIGHT(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k[i] + schedule[i];
        uint32_t S0 = ROTRIGHT(a, 2) ^ ROTRIGHT(a, 13) ^ ROTRIGHT(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    /* Add the compressed chunk to the current hash value */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* SHA-256 padding and pre-processing */
static void sha256_padding(size_t len, uint8_t* padded_data) {
    // Append a single 1-bit to the message
    padded_data[len] = 0x80;

    /*Pad with zeros*/ 
    for (size_t i = len + 1; i < 56; ++i) {
        padded_data[i] = 0;
    }

    /*Add message length in bits as 64-bit big-endian integer*/
    uint64_t total_len = len * 8;
    for (size_t i = 0; i < 8; ++i) {
        padded_data[56 + i] = (total_len >> (56 - i * 8)) & 0xFF;
    }
}

void sha256(const uint8_t* data, size_t len, uint8_t* output) {
    /* Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes) */
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t padded_data[64]; /* 512-bit blocks for SHA-256 */
    memcpy(padded_data, data, len);
    sha256_padding(len, padded_data);
    sha256_transform(padded_data, state);

    /* Convert the final state to little-endian bytes and copy it to the output buffer*/
    for (int i = 0; i < 8; ++i) {
        output[i * 4 + 0] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }
}
