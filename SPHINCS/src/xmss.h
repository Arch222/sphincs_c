
#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>


#define XMSS_SUBTREE_HEIGHT 4  // Height of each subtree
#define HASH_BYTES 32
#define XMSS_HEIGHT 10
#define XMSS_NUM_SUBTREES (XMSS_HEIGHT / XMSS_SUBTREE_HEIGHT) // Number of subtrees


// XMSS public key structure for multi-tree variant
typedef struct {
    uint8_t root[HASH_BYTES];
} xmss_multitree_public_key;

// XMSS secret key structure for multi-tree variant
typedef struct {
    uint8_t sk[HASH_BYTES];
    uint32_t idx; // Secret key index for multi-tree variant
} xmss_multitree_secret_key;

// XMSS signature structure for multi-tree variant
typedef struct {
    uint8_t leaf[HASH_BYTES];
    uint8_t auth_path[XMSS_NUM_SUBTREES][XMSS_SUBTREE_HEIGHT][HASH_BYTES];
} xmss_multitree_signature;

int xmss_keygen(xmss_multitree_public_key *pk, xmss_multitree_secret_key *sk, const uint8_t *seed);
int xmss_sign(xmss_multitree_signature *sig, const uint8_t *msg, xmss_multitree_secret_key *sk, const uint8_t *seed);
int xmss_verify(const xmss_multitree_signature *sig, const uint8_t *msg, const xmss_multitree_public_key *pk);

// Serialization and Deserialization Functions
void serialize_xmss_multitree_public_key(const xmss_multitree_public_key *pk, uint8_t *output, uint32_t *offset);
void deserialize_xmss_multitree_public_key(xmss_multitree_public_key *pk, const uint8_t *input, uint32_t *offset);

#endif // XMSS_H
