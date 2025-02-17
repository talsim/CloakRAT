#include "iostream"
#include "array"
#include "string_encryption.h"

// We will encrypt with a XOR key at compile-time
// At runtime, we will introduce a dynamic key that will replace the compile-time encryption and be random - the effective XOR key.
// Then we will re-encrypt the strings on program startup (maybe in the tls callback) using the effective key.

std::array<uint8_t, RUNTIME_KEY_LENGTH> generate_dynamic_key()
{
	std::array<uint8_t, RUNTIME_KEY_LENGTH> dynamic_key = {};
	std::random_device rd;
	for (int i = 0; i < RUNTIME_KEY_LENGTH; i++)
		dynamic_key[i] = (uint8_t)(rd() & 0xFF);
	return dynamic_key;
}


