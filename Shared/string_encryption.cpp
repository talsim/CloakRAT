#include "string_encryption.h"

// We will encrypt with a XOR key at compile-time
// At runtime, we will introduce a dynamic key that will replace the compile-time encryption and be random - the effective XOR key.
// Then we will re-encrypt the strings on program startup (maybe in the tls callback) using the effective key.

std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key() // TODO: Might be better inlined for stealth cuz this is a super sensitive func
{
	std::array<uint8_t, DYNAMIC_KEY_LENGTH> runtime_key = {}; // dynamic key
	std::random_device rd; // Used as the seed
	std::mt19937 rng(rd()); // Our PRNG 
	std::uniform_int_distribution<int> dist(0, 255); // Get random numbers between 0 to 255 (1 byte)

	for (int i = 0; i < DYNAMIC_KEY_LENGTH; i++)
	{
		small_junk();
		runtime_key[i] = (uint8_t)(dist(rng));

		// junk
		if (runtime_key[i] % 2 == 1 || junk_var_2) 
			suspicious_junk_3();
		else
			junk();
	}

	return runtime_key;
}

void runtime_reencryption(char* data, size_t data_length)
{
	/*
	* Our compile-time encryption: E = string XOR compile_time_key
	* We want final data:          E' = string XOR dynamic_key
	* Thus, the runtime re-encryption is as follows: data[i] ^ (compile_time_key[i] ^ dynamic_key[i])
	* where data = E
	*/
	
	junk();
	std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamic_key = generate_runtime_key();
	for (int i = 0; i < data_length; i++)
	{
		suspicious_junk_1();
		
		data[i] = data[i] ^ (char)(COMPILE_TIME_CIPHER ^ dynamic_key[i % DYNAMIC_KEY_LENGTH]/* TODO: define a macro like RUNTIME_CIPHER*/);
	}
}


std::string decrypt(char* data, size_t data_length)
{
	std::string result = "";

	// TODO: Implement.

	return result;
}


