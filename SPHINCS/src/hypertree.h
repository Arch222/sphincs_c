
#ifndef HYPERTREE_H
#define HYPERTREE_H

#include <stdint.h>
#include "xmss.h"
#include "fors.h"

#define HYPERTREE_LAYERS 5 // Number of layers in the Hypertree

// Hypertree public key structure
typedef struct {
    uint8_t root[HASH_BYTES]; // Root of the Hypertree
} hypertree_public_key;

// Hypertree secret key structure
typedef struct {
    xmss_multitree_secret_key layers[HYPERTREE_LAYERS]; // Secret keys for each layer
} hypertree_secret_key;

// Hypertree signature structure
typedef struct {
    fors_signature fors_sig; // FORS signature
    xmss_multitree_signature xmss_sigs[HYPERTREE_LAYERS - 1]; // XMSS signatures for each layer
} hypertree_signature;

int hypertree_keygen(hypertree_public_key *pk, hypertree_secret_key *sk, const uint8_t *seed);
int hypertree_sign(hypertree_signature *sig, const uint8_t *msg, hypertree_secret_key *sk, const uint8_t *seed);
int hypertree_verify(const hypertree_signature *sig, const uint8_t *msg, const hypertree_public_key *pk);

#endif // HYPERTREE_H
