#include <stdio.h>
#include "rng.h"

int main() {
    // Define a seed
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    // Initialize the RNG with the seed
    rng_init(seed);

    // Define a buffer to hold at least 2000 random bytes
    uint8_t buffer[2000];

    // Generate the random bytes
    rng_generate(buffer, sizeof(buffer));

    // Print the first 10 random bytes as an example
    printf("First 10 random bytes: ");
    for (int i = 0; i < 10; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\\n");

    // Add additional tests or analyses if required

    return 0;
}
