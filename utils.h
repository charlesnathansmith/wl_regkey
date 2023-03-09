#pragma once

/*********************************************
*
* WL File Key Demo
* Utilities needed by the license generator
*
*********************************************/

#include <stdint.h>

// Macros to make pointer references into buffers easier
#define pbyte(x) *((uint8_t*)(x))
#define pword(x) *((uint16_t*)(x))
#define pdword(x) *((uint32_t*)(x))

// Random number generator
uint32_t rnd();

// String checksum
uint16_t str_checksum(const char* str);

// Binary checksum
uint16_t bin_checksum(const uint8_t* buf, size_t size);

// Rotate right
uint32_t ror32(uint32_t value, uint8_t amount);

// Rotate left
uint32_t rol32(uint32_t value, uint8_t amount);
