
#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>
#include "sha256.h"
#include <string.h>

#define WOTS_W 16
#define WOTS_LOGW 4
#define WOTS_LEN 67

// Function prototypes
void wots_generate_private_key(uint8_t* private_key);
void wots_generate_public_key(const uint8_t* private_key, uint8_t* public_key);
void wots_sign(const uint8_t* message, const uint8_t* private_key, uint8_t* signature);
int wots_verify(const uint8_t* message, const uint8_t* signature, const uint8_t* public_key);

#endif