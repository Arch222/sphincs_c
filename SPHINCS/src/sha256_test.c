#include <stdio.h>
#include <string.h>
#include "sha256.h"

/* Function to compare two arrays of bytes */
int compare_bytes(const uint8_t* arr1, const uint8_t* arr2, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (arr1[i] != arr2[i]) {
            return 0;
        }
    }
    return 1;
}

/* Function to execute the SHA-256 hash on a certain message input */
void test_sha256() {
    /* Test vectors with message inputs and expected outputs */
    struct TestVector {
        const char* input;
        const uint8_t output[SHA256_DIGEST_SIZE];
    };

struct TestVector test_vectors[] = {
    { "abc", {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    } },
    { "Hello, world!", {
        0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4,
        0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64,
        0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34,
        0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3
    } },
    /* Add more test vectors if need be. */
};

    size_t num_test_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

    /* Buffer to hold the output of the SHA-256 hash */
    uint8_t output[SHA256_DIGEST_SIZE];

    /* Run the tests and compare results */
    for (size_t i = 0; i < num_test_vectors; ++i) {
        sha256((const uint8_t*)test_vectors[i].input, strlen(test_vectors[i].input), output);
        if (compare_bytes(output, test_vectors[i].output, SHA256_DIGEST_SIZE)) {
            printf("Test %d passed!\n", i + 1);
        } else {
            printf("Test %d failed!\n", i + 1);
        }
    }
}

int main() {
    /* Call the function to test SHA-256 implementation */
    test_sha256();
    return 0;
}