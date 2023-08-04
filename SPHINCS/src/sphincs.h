#ifndef SPHINCS_H
#define SPHINCS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fors.h" // Assuming FORS is already defined
#include "xmss.h" // Assuming XMSS is already defined
#include "sha256.h"

#define HYPER_LAYERS 5 // Number of layers in the hypertree
#define HASH_BYTES 32 // Hash size in bytes

// SPHINCS+ public key structure
typedef struct {
    fors_public_key fors_public_key;
    xmss_multitree_public_key xmss_pk[HYPER_LAYERS];
    uint8_t root[HASH_BYTES];
} sphincs_public_key;

// SPHINCS+ secret key structure
typedef struct {
    fors_secret_key fors_secret_key;
    xmss_multitree_secret_key xmss_sk[HYPER_LAYERS];
} sphincs_secret_key;

// SPHINCS+ signature structure
typedef struct {
    fors_signature fors_signature;
    xmss_multitree_signature xmss_sig[HYPER_LAYERS];
} sphincs_signature;

// Function declarations
void sphincs_keygen(sphincs_public_key *pk, sphincs_secret_key *sk, const uint8_t *seed);
void sphincs_sign(sphincs_signature *sig, const uint8_t *msg, const sphincs_secret_key *sk);
int sphincs_verify(const sphincs_signature *sig, const uint8_t *msg, const sphincs_public_key *pk);

#endif // SPHINCS_H
