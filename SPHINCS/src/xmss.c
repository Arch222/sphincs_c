
#include "xmss.h"
#include "sha256.h"
#include "rng.h"
#include "wots.h"  // Including WOTS+ for leaf computation
#include <string.h>
#include <stdlib.h>

#define XMSS_HEIGHT 10
#define HASH_BYTES 32
#define XMSS_SUBTREE_HEIGHT 4  // Height of each subtree
#define XMSS_NUM_SUBTREES (XMSS_HEIGHT / XMSS_SUBTREE_HEIGHT) // Number of subtrees


// XMSS public key structure for multi-tree variant
typedef struct {
    uint8_t root[HASH_BYTES];
} xmss_public_key;

// XMSS secret key structure for multi-tree variant
typedef struct {
    uint8_t sk[HASH_BYTES];
    uint32_t leaf_idx; // Secret key index for multi-tree variant
} xmss_secret_key;

// XMSS signature structure for multi-tree variant
typedef struct {
    uint8_t leaf[HASH_BYTES];
    uint8_t auth_path[XMSS_NUM_SUBTREES][XMSS_SUBTREE_HEIGHT][HASH_BYTES];
} xmss_signature;


void serialize_byte_array(const uint8_t *array, uint32_t length, uint8_t *output, uint32_t *offset) {
    memcpy(output + *offset, &length, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    memcpy(output + *offset, array, length);
    *offset += length;
}

void deserialize_byte_array(uint8_t *array, uint32_t *length, const uint8_t *input, uint32_t *offset) {
    memcpy(length, input + *offset, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    memcpy(array, input + *offset, *length);
    *offset += *length;
}

void serialize_xmss_multitree_public_key(const xmss_multitree_public_key *pk, uint8_t *output, uint32_t *offset) {
    serialize_byte_array(pk->root, HASH_BYTES, output, offset);
}

void deserialize_xmss_multitree_public_key(xmss_multitree_public_key *pk, const uint8_t *input, uint32_t *offset) {
    uint32_t length;
    deserialize_byte_array(pk->root, &length, input, offset);
}



static void compute_wots_leaf(uint8_t *leaf) {
    uint8_t wots_sk[WOTS_LEN * HASH_BYTES];
    wots_generate_private_key(wots_sk); // Generate WOTS+ private key
    wots_generate_public_key(wots_sk, leaf); // Compute WOTS+ public key (the XMSS leaf)
}


static void xmss_thash(uint8_t* left, uint8_t* right, uint8_t* parent) {
    uint8_t buffer[2 * HASH_BYTES];
    memcpy(buffer, left, HASH_BYTES);
    memcpy(buffer + HASH_BYTES, right, HASH_BYTES);
    sha256(buffer, 2 * HASH_BYTES, parent);
}
static void compute_subtree_root(uint32_t subtree_idx, uint8_t *root) {
    uint32_t start_idx = subtree_idx << XMSS_SUBTREE_HEIGHT;
    uint32_t end_idx = start_idx + (1 << XMSS_SUBTREE_HEIGHT);

    // Temporary storage for tree nodes
    uint8_t nodes[1 << (XMSS_SUBTREE_HEIGHT + 1)][HASH_BYTES];

    // Compute WOTS+ leaves for the subtree
    for (uint32_t i = start_idx; i < end_idx; i++) {
        compute_wots_leaf(nodes[i - start_idx]);
    }

    // Compute the subtree using a binary tree approach
    for (int h = 0; h < XMSS_SUBTREE_HEIGHT; h++) {
        for (int i = 0; i < (1 << (XMSS_SUBTREE_HEIGHT - h)) / 2; i++) {
            xmss_thash(nodes[2 * i + (1 << h)], nodes[2 * i + 1 + (1 << h)], nodes[i + (1 << (h + 1))]);
        }
    }

    // Copy the subtree root to the output
    memcpy(root, nodes[1 << XMSS_SUBTREE_HEIGHT], HASH_BYTES);
}


void xmss_multitree_compute_tree(uint8_t *root) {
    uint8_t subtree_roots[XMSS_NUM_SUBTREES][HASH_BYTES];

    // Compute the roots of all subtrees
    for (uint32_t i = 0; i < XMSS_NUM_SUBTREES; i++) {
        compute_subtree_root(i, subtree_roots[i]);
    }

    // Build the main tree from the subtree roots using a binary tree approach
    uint8_t nodes[1 << (XMSS_HEIGHT - XMSS_SUBTREE_HEIGHT + 1)][HASH_BYTES];
    memcpy(nodes, subtree_roots, sizeof(subtree_roots));
    for (int h = 0; h < XMSS_HEIGHT - XMSS_SUBTREE_HEIGHT; h++) {
        for (int i = 0; i < (1 << (XMSS_HEIGHT - XMSS_SUBTREE_HEIGHT - h)) / 2; i++) {
            xmss_thash(nodes[2 * i + (1 << h)], nodes[2 * i + 1 + (1 << h)], nodes[i + (1 << (h + 1))]);
        }
    }

    // Copy the main tree root to the output
    memcpy(root, nodes[1 << (XMSS_HEIGHT - XMSS_SUBTREE_HEIGHT)], HASH_BYTES);
}


static void xmss_compute_auth_path(uint32_t leaf_idx, uint8_t auth_path[XMSS_NUM_SUBTREES][XMSS_SUBTREE_HEIGHT][HASH_BYTES]) {
    // Define the tree structure, possibly as an array of nodes
    uint8_t tree[1 << (XMSS_HEIGHT + 1)][HASH_BYTES]; // Example representation

    // Iterate through the subtrees
    for (int subtree = 0; subtree < XMSS_NUM_SUBTREES; subtree++) {
        uint32_t idx_in_subtree = leaf_idx & ((1 << XMSS_SUBTREE_HEIGHT) - 1);

        // Iterate through the levels of the subtree
        for (int level = 0; level < XMSS_SUBTREE_HEIGHT; level++) {
            uint32_t node_idx = idx_in_subtree >> level;
            

            // Compute the left and right children
            uint8_t *left_child = tree[(node_idx & ~1) << level];
            uint8_t *right_child = tree[(node_idx | 1) << level];

            // Store the sibling in the auth_path
            if (node_idx & 1) {
                memcpy(auth_path[subtree][level], left_child, HASH_BYTES);
            } else {
                memcpy(auth_path[subtree][level], right_child, HASH_BYTES);
            }

            // Compute the parent node using SHA-256
            uint8_t parent[HASH_BYTES];
            uint8_t children[2 * HASH_BYTES];
            memcpy(children, left_child, HASH_BYTES);
            memcpy(children + HASH_BYTES, right_child, HASH_BYTES);
            sha256(children, 2 * HASH_BYTES, parent);

            // Store the parent in the tree
            memcpy(&tree[node_idx >> 1][level + 1], parent, HASH_BYTES);
        }

        // Move to the next subtree
        leaf_idx >>= XMSS_SUBTREE_HEIGHT;
    }
}


// Function to generate XMSS public and secret keys
int xmss_keygen(xmss_multitree_public_key *pk, xmss_multitree_secret_key *sk, const uint8_t *seed) {
    if (!pk || !sk || !seed) return -1; // Error handling

    // Generate XMSS secret key seed
    rng_generate(sk->sk, HASH_BYTES);

    // Initialize secret key index
    sk->idx = 0;

    // Compute the XMSS multi-tree root
    xmss_multitree_compute_tree(pk->root);

    return 0; // Success
}

// Function to sign a message using XMSS
int xmss_sign(xmss_multitree_signature *sig, const uint8_t *msg, xmss_multitree_secret_key *sk, const uint8_t *seed) {
    if (!sig || !msg || !sk || !seed) return -1; // Error handling
    
    uint32_t leaf_idx = sk->idx; // Secret key index (leaf index)

    // Check for index overflow
    if (leaf_idx >= (1u << XMSS_HEIGHT)) return -2; // All indices exhausted

    // Compute the leaf corresponding to the secret key index
    compute_wots_leaf(sig->leaf);

    // Compute the authentication path for the given leaf index
    xmss_compute_auth_path(leaf_idx, sig->auth_path);

    // Increment the secret key index
    sk->idx++;

    return 0; // Success
}


// Function to compute the root of a subtree given a leaf index and authentication path
static void xmss_treehash(const uint8_t* leaf, uint32_t leaf_idx, int h, const uint8_t auth_path[XMSS_SUBTREE_HEIGHT][HASH_BYTES], uint8_t* root) {
    uint8_t buffer[2 * HASH_BYTES];
    memcpy(buffer, leaf, HASH_BYTES);
    
    for (int i = 0; i < h; i++) {
        if (leaf_idx & 1) {
            memcpy(buffer + HASH_BYTES, auth_path[i], HASH_BYTES);
        } else {
            memcpy(buffer, auth_path[i], HASH_BYTES);
        }
        sha256(buffer, 2 * HASH_BYTES, buffer);
        leaf_idx >>= 1;
    }
    memcpy(root, buffer, HASH_BYTES);
}

int xmss_verify(const xmss_multitree_signature *sig, uint8_t leaf_idx, const uint8_t *msg, const xmss_multitree_public_key *pk) {
    if (!sig || !msg || !pk) return -1;

    // Recompute the root from the signature
    uint8_t computed_root[HASH_BYTES];
    xmss_treehash(sig->leaf, leaf_idx, XMSS_HEIGHT, sig->auth_path[0], computed_root);

    // Compare the recomputed root to the public key
    return memcmp(computed_root, pk->root, HASH_BYTES) == 0;
}
