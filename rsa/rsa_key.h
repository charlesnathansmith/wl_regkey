#pragma once

/*****
*
* WL File Key Demo
*
* Bare-bones RSA implementation to handle license signing and encryption
* Key parsing and management
* 
 *****/

#include <stdint.h>
#include "libtommath/tommath.h"

// Base36 decode an ASCII string
bool base36_decode(const char* in, uint8_t* out, size_t out_size);

// Read an integer from a DER stream
size_t read_der_int(mp_int* n, uint8_t* der, uint8_t* end);

class rsa_private_key
{
private:
	mp_int _n, _d;				// modulus, private exponent
	
public:
	rsa_private_key() { mp_init_multi(&_n, &_d, NULL); }

	// From DER, base36-encoded ascii
	rsa_private_key(const char* ascii_key);

	// Copy and assignment
	rsa_private_key(const rsa_private_key& rhs);
	rsa_private_key& operator=(const rsa_private_key& rhs);

	~rsa_private_key() { mp_clear_multi(&_n, &_d, NULL); }

	// Extract private key from a DER-encoded packet
	bool import_from_der(uint8_t* der, size_t size);

	// Extracts private key from a base-36 encoded, DER-encoded ASCII string
	bool import_from_base36der(const char* in);

	// Get modulus and private exponents
	const mp_int* n() const { return static_cast<const mp_int*>(&_n); }
	const mp_int* d() const { return static_cast<const mp_int*>(&_d); }

	// Get modulus size in bytes
	size_t size() const { return mp_count_bits(&_n) / 8;  }
};
