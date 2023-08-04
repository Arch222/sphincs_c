#ifndef FORS_H
#define FORS_H

#include <stdint.h>

#define FORS_K  // Number of trees
#define FORS_HEIGHT  // Height of each tree
#define HASH_BYTES 32  // Hash output size in bytes
#define FORS_T 8
#define FORS_THRES 70
#define FORS_SAMPLES 16

// FORS public key structure
typedef struct {
    uint8_t root[FORS_K][HASH_BYTES];
} fors_public_key;

// FORS secret key structure
typedef struct {
    uint8_t sk[FORS_K][HASH_BYTES];
} fors_secret_key;

// FORS signature structure
typedef struct {
    struct {
        uint8_t sig[HASH_BYTES];
        uint8_t auth_path[FORS_HEIGHT][HASH_BYTES];
    } signatures[FORS_K];
} fors_signature;

// Function prototypes
void fors_keygen(fors_public_key *pk, fors_secret_key *sk, const uint8_t *seed);
int fors_sign(fors_signature *sig, const uint8_t *msg, const fors_secret_key *sk, const uint8_t *seed);
int fors_verify(const fors_signature *sig, const uint8_t *msg, const fors_public_key *pk);

#endif // FORS_H
