
#include "hypertree.h"

// Function to generate Hypertree public and secret keys
int hypertree_keygen(hypertree_public_key *pk, hypertree_secret_key *sk, const uint8_t *seed) {
    if (!pk || !sk || !seed) return -1;

    // Generate secret keys for each layer
    for (int i = 0; i < HYPERTREE_LAYERS; i++) {
        if (xmss_keygen(&pk->root, &sk->layers[i], seed) != 0) {
            return -2;
        }
    }

    return 0;
}

// Function to sign a message using Hypertree
int hypertree_sign(hypertree_signature *sig, const uint8_t *msg, hypertree_secret_key *sk, const uint8_t *seed) {
    if (!sig || !msg || !sk || !seed) return -1;

    // Compute the FORS signature for the message
    if (fors_sign(&sig->fors_sig, msg, &sk->layers[0], seed) != 0) {
        return -2;
    }

    uint8_t root[HASH_BYTES];
    fors_public_key_from_signature(root, &sig->fors_sig, msg);

    // Compute the XMSS signature for each layer of the Hypertree
    for (int i = 0; i < HYPERTREE_LAYERS - 1; i++) {
        xmss_multitree_signature *xmss_sig = &sig->xmss_sigs[i];
        if (xmss_sign(xmss_sig, root, &sk->layers[i + 1], seed) != 0) {
            return -3;
        }
        xmss_treehash(xmss_sig->leaf, xmss_sig->leaf_idx, XMSS_HEIGHT, xmss_sig->auth_path, root);
    }

    return 0;
}

// Function to verify a Hypertree signature
int hypertree_verify(const hypertree_signature *sig, const uint8_t *msg, const hypertree_public_key *pk) {
    if (!sig || !msg || !pk) return -1;

    uint8_t root[HASH_BYTES];
    fors_public_key_from_signature(root, &sig->fors_sig, msg);

    // Verifying the XMSS signatures in each layer of the Hypertree
    for (int i = 0; i < HYPERTREE_LAYERS - 1; i++) {
        const xmss_multitree_signature *xmss_sig = &sig->xmss_sigs[i];
        if (xmss_verify(xmss_sig, root, &pk->root) != 0) {
            return -2;
        }
        xmss_treehash(xmss_sig->leaf, xmss_sig->leaf_idx, XMSS_HEIGHT, xmss_sig->auth_path, root);
    }

    // Comparing the recomputed root to the public key
    return memcmp(root, pk->root, HASH_BYTES) == 0;
}
