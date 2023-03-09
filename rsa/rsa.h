#pragma once

/*****
* 
* WL File Key Demo
* 
* Bare-bones RSA implementation to handle license signing and encryption
* 
* libtomcrypt would've been the obvious choice, but we don't need 95% of it,
* and its includes don't follow the directory structure so the compiler environment
* would have to be adjusted around it.  This does what we need.
* 
 *****/

#include "rsa_key.h"

constexpr unsigned int CRYPT_OK = 0;

// Computes SHA-1 digest
void sha1(uint8_t* const in, size_t in_size, uint8_t* out);

// Generate SHA-1 message for RSA signing
bool rsa_sha1_msg(uint8_t* const in, size_t in_size, size_t mod_size, uint8_t* out);

// RSA encrypt block of up to modulus size
bool rsa_exptmod(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t* out_size);

// RSA sign a message using SHA-1
bool rsa_sign(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t out_size);
