# sphincs_c
A custom, high-level implementation of the SPHINCS+ post-quantum cryptography scheme. 

This is a very rough, in progress implementation of the SPHINCS+ post-quantum cryptography scheme. The eventual goal for this library is for it to be a counterpart to the secp256k1 library created by Peter Todd and maintained by the Bitcoin Core Developers.

Just as the secp256k1 library has become a standard for use within cryptocurrency-based projects and other similar implementations, the goal is for this library to be the same for projects seeking to implement a hash-based, post-quantum secure signature scheme. 

Note that this just beginning, and is most likely not close to being usable in a production-based setting. The ultimate vision is to have more extensive testing available, easy to call APIs that ensure potential developers don't make mistakes when integrating, and add additional safety/efficiency optimizations.

## Goals
* Ensure that everything works as expected, especially when compared to known test vectors.
* Integrate additional testing.
* Optimize for C89 compilation, and removal of additional, unused code.

  
