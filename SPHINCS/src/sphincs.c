#include <stdlib.h>
#include "sphincs.h"
#include <string.h>

void sphincs_keygen(sphincs_public_key *pk, sphincs_secret_key *sk, const uint8_t *seed) {
    fors_keygen(&pk->fors_pk, &sk->fors_sk, seed);
    for (int i = 0; i < HYPER_LAYERS; ++i) {
        xmss_keygen(&pk->xmss_pk[i], &sk->xmss_sk[i], seed);
    }
    hypertree_compute_root(pk->root, pk->xmss_pk);
}

void sphincs_sign(sphincs_signature *sig, const uint8_t *msg, const sphincs_secret_key *sk) {
    uint8_t hashed_msg[HASH_BYTES];
    sha256(msg, strlen(msg), hashed_msg);
    fors_sign(&sig->fors_sig, hashed_msg, &sk->fors_sk);
    for (int i = 0; i < HYPER_LAYERS; ++i) {
        xmss_sign(&sig->xmss_sig[i], hashed_msg, &sk->xmss_sk[i]);
    }
}

int sphincs_verify(const sphincs_signature *sig, const uint8_t *msg, const sphincs_public_key *pk) {
    uint8_t hashed_msg[HASH_BYTES];
    sha256(msg, strlen(msg), hashed_msg);
    if (!fors_verify(&sig->fors_sig, hashed_msg, &pk->fors_pk)) {
        return 0;
    }
    for (int i = 0; i < HYPER_LAYERS; ++i) {
        if (!xmss_verify(&sig->xmss_sig[i], hashed_msg, &pk->xmss_pk[i])) {
            return 0;
        }
    }
    uint8_t computed_root[HASH_BYTES];
    hypertree_compute_root(computed_root, pk->xmss_pk);
    return memcmp(computed_root, pk->root, HASH_BYTES) == 0;
}
