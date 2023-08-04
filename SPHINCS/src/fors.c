#include "fors.h"
#include "wots.h"
#include <string.h>
#include "sha256.h"

// Constants for error codes
#define FORS_SUCCESS 0
#define FORS_NULL_POINTER -1
#define FORS_INVALID_SIGNATURE -2


// Function to compute a FORS tree root
static void fors_treehash(const uint8_t* leaf, uint32_t leaf_idx, int h, const uint8_t* auth_path, uint8_t* root) {
    uint8_t buffer[2 * HASH_BYTES];
    memcpy(buffer, leaf, HASH_BYTES);
    
    for (int i = 0; i < h; i++) {
        if (leaf_idx & 1) {
            // Hash the sibling (from the authentication path) with the current node
            memcpy(buffer + HASH_BYTES, auth_path + i * HASH_BYTES, HASH_BYTES);
        } else {
            // Hash the current node with the sibling (from the authentication path)
            memcpy(buffer, auth_path + i * HASH_BYTES, HASH_BYTES);
        }
        // Update the current node
        sha256(buffer, 2 * HASH_BYTES, buffer);
        leaf_idx >>= 1;
    }
    memcpy(root, buffer, HASH_BYTES);
}

// Function to generate FORS public and secret keys
void fors_keygen(fors_public_key *pk, fors_secret_key *sk, const uint8_t *seed) {
    if (!pk || !sk || !seed) return;

    // Generate WOTS+ secret keys
    uint8_t wots_seeds[FORS_T][HASH_BYTES];
    wots_generate_secret_keys(wots_seeds, seed);

    // Generate WOTS+ public keys and concatenate them to form the FORS public key
    uint8_t wots_pub_keys[FORS_T][WOTS_W * HASH_BYTES];
    wots_generate_public_keys(wots_pub_keys, wots_seeds);
    memcpy(pk->root, wots_pub_keys, FORS_T * WOTS_W * HASH_BYTES);

    // Store the WOTS+ secret keys in the FORS secret key
    memcpy(sk->sk, wots_seeds, FORS_T * HASH_BYTES);
}

// Function to sign a message using FORS
int fors_sign(fors_signature *sig, const uint8_t *msg, const fors_secret_key *sk, const uint8_t *seed) {
    if (!sig || !msg || !sk || !seed) return FORS_NULL_POINTER;

    // Generate WOTS+ secret keys
    uint8_t wots_seeds[FORS_T][HASH_BYTES];
    wots_generate_secret_keys(wots_seeds, seed);

    // Generate WOTS+ public keys and concatenate them to form the FORS public key
    uint8_t wots_pub_keys[FORS_T][WOTS_W * HASH_BYTES];
    wots_generate_public_keys(wots_pub_keys, wots_seeds);
    memcpy(sig->pk.root, wots_pub_keys, FORS_T * WOTS_W * HASH_BYTES);

    // Store the WOTS+ secret keys in the FORS secret key
    memcpy(sig->sk.sk, wots_seeds, FORS_T * HASH_BYTES);

    // Compute the authentication path for each WOTS+ instance
    uint32_t leaf_idx = 0;
    for (int i = 0; i < FORS_T; i++) {
        uint8_t leaf[HASH_BYTES];
        wots_sign(leaf, msg, &(sk->sk[i]), &(seed[i * HASH_BYTES]));
        fors_treehash(leaf, leaf_idx, FORS_HEIGHT, NULL, sig->auth_path[i]);
        leaf_idx += (1 << FORS_HEIGHT);
    }

    return FORS_SUCCESS;
}

// Function to verify a FORS signature
int fors_verify(const fors_signature *sig, const uint8_t *msg, const fors_public_key *pk) {
    if (!sig || !msg || !pk) return FORS_NULL_POINTER;

    // Verify the authentication path
    uint32_t leaf_idx = 0;
    for (int i = 0; i < FORS_T; i++) {
        uint8_t leaf[HASH_BYTES];
        wots_verify(leaf, msg, &(sig->pk.root[i * WOTS_W * HASH_BYTES]), &(sig->auth_path[i]));
        uint8_t computed_root[HASH_BYTES];
        fors_treehash(leaf, leaf_idx, FORS_HEIGHT, sig->auth_path[i], computed_root);
        if (memcmp(computed_root, &(pk->root[i * WOTS_W * HASH_BYTES]), HASH_BYTES) != 0) {
            return FORS_INVALID_SIGNATURE;
        }
        leaf_idx += (1 << FORS_HEIGHT);
    }

    return FORS_SUCCESS;
}