#include "string_encryption.h"

// We will encrypt with a XOR key at compile-time
// At runtime, we will introduce a dynamic key that will replace the compile-time encryption and be random - the effective XOR key.
// Then we will re-encrypt the strings on program startup (maybe in the tls callback) using the effective key.

std::array<uint8_t, RUNTIME_KEY_LENGTH> generate_dynamic_key()
{
	small_junk();
	std::array<uint8_t, RUNTIME_KEY_LENGTH> dynamic_key = {};
	std::random_device rd; // Used as the seed
	std::mt19937 rng(rd()); // Our PRNG 
	std::uniform_int_distribution<int> dist(0, 255); // Get random numbers between 0 to 255 (1 byte)

	for (int i = 0; i < RUNTIME_KEY_LENGTH; i++)
	{
		dynamic_key[i] = (uint8_t)(dist(rng));

		// junk
		if (dynamic_key[i] % 2 == 1 || junk_var_2) 
			suspicious_junk_3();
		else
			junk();
	}

	return dynamic_key;
}


