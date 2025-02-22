#include "string_encryption.h"

// We will encrypt with a XOR key at compile-time
// At runtime, we will introduce a dynamic key that will replace the compile-time encryption and be random - the effective XOR key.
// Then we will re-encrypt the strings on program startup (maybe in the tls callback) using the effective key.

#define RUNTIME_CIPHER_BYTE (char)((((i * 13 + i * i) >> i) - dynamicKey[i % DYNAMIC_KEY_LENGTH]) ^ 0xD3) // random ops to avoid XORing with just the key
#define CHUNK_SIZE 6 // Lower chunk size means more iterations and random cycles

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

		// dummy code
		if (runtime_key[i] % 2 == 1 || junk_var_2)
			suspicious_junk_3();
		else
			junk();
	}

	return runtime_key;
}

void runtime_reencryption(char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey)
{
	/*
	* Our compile-time encryption: E = string XOR compile_time_key
	* We want final data:          E' = string XOR dynamic_key
	* Thus, the runtime re-encryption is as follows: data[i] ^ (compile_time_key[i] ^ dynamic_key[i])
	* where data = E
	*/

	// Spilt the data to chunks, and shuffle the chunks order to re-encrypt the data at random chunks, instead of a linear loop (less obvious).
	size_t chunksNum = (dataLength + CHUNK_SIZE - 1) / CHUNK_SIZE; // round up to include an extra chunk for the remainder
	std::vector<size_t> chunkIndexes(chunksNum);

	for (int i = 0; i < chunksNum; i++)
		chunkIndexes[i] = i;

	std::random_device rd;
	std::mt19937 rng(rd());
	small_junk();
	std::shuffle(chunkIndexes.begin(), chunkIndexes.end(), rng); // Shuffle the chunk indexes to avoid a linear loop

	junk();

	for (size_t chunkIndex : chunkIndexes) // random cycles on the data
	{
		size_t startIdx = chunkIndex * CHUNK_SIZE;
		size_t endIdx = startIdx + CHUNK_SIZE < dataLength ? startIdx + CHUNK_SIZE : dataLength; // min(startIdx + CHUNK_SIZE, dataLength)

		suspicious_junk_1();
		for (size_t i = startIdx; i < endIdx; i++)
		{
			data[i] = data[i] ^ (char)(COMPILE_TIME_CIPHER_BYTE ^ RUNTIME_CIPHER_BYTE); // The compiler will optimize all the operations here, obfuscating the compile time cipher further.
		}
	}
	// Now data is encrypted as: data XOR dynamic_key.
}


std::string decrypt_bytes(char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey)
{
	std::string result = "";
	result.resize(dataLength - 1); // Allocate space in the string without the null terminator (the null terminator is encrypted too)

	// Decrypt the data in random chunks of CHUNK_SIZE, and not linearly
	// Important note - the decryption order will be randomized differently from the encryption order of the bytes, but it doesn't matter because each byte transformation is independent of other elements, but only its current iteration.
	size_t chunksNum = (dataLength + CHUNK_SIZE - 1) + CHUNK_SIZE; // round up for the remainder
	std::vector<size_t> chunkIndexes(chunksNum);

	for (int i = 0; i < chunksNum; i++)
		chunkIndexes[i] = i;

	std::random_device rd;
	std::mt19937 rng(rd());
	std::shuffle(chunkIndexes.begin(), chunkIndexes.end(), rng); // Shuffle the chunk indexes 

	for (size_t chunkIndex : chunkIndexes) // random cycles on the data
	{
		size_t startIdx = chunkIndex * CHUNK_SIZE;
		size_t endIdx = startIdx + CHUNK_SIZE < dataLength ? startIdx + CHUNK_SIZE : dataLength;

		for (size_t i = startIdx; i < endIdx; i++)
		{
			// TODO: Add junk code
			result[i] = (char)(data[i] ^ RUNTIME_CIPHER_BYTE);
		}
	}

	return result;
}


