#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

void sha256(const uint8_t* data, size_t len, uint8_t* output);

#endif // SHA256_H
