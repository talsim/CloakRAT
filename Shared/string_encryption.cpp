#include <random>
#include "string_encryption.h"
#include "junk_codes.h"

// We encrypt with a XOR key at build-time (in the python script)
// At runtime, we introduce a dynamic key that will replace the build-time encryption and be random - the effective XOR key.
// Then we will re-encrypt the strings on the first use (A dedicated bit is set in each runtime-reencrypted string after re-encryption) using a static per translation unit key.

#define RUNTIME_CIPHER_BYTE (unsigned char)((((i * 13 + i * i) >> (i % 8)) - dynamicKey[i % DYNAMIC_KEY_LENGTH]) ^ 0xD3) // random ops to avoid XORing with just the key
#define CHUNK_SIZE 6 // Lower chunk size means more iterations and random cycles

inline std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key()
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
			junk_var_2 = not_inlined_junk_func_4();
		else
			junk_var_2 ^= junk_var_1;
	}

	return runtime_key;
}

void runtime_reencryption(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey) 
{
	/*
	* Our build-time encryption: E = string XOR BUILD_TIME_CIPHER_BYTE
	* We want final data:          E' = string XOR RUNTIME_CIPHER_BYTE
	* Thus, the runtime re-encryption is as follows: data[i] ^ (BUILD_TIME_CIPHER_BYTE[i] ^ RUNTIME_CIPHER_BYTE[i])
	* where data = E.
	* 
	* It also sets the the highest bit in the preserved first byte to indicate that the string was already reencrypted.
	*/
	
	if (data[0] & 0x80) // If the reencryption has already happenend
		return;

	// Spilt the data to chunks, and shuffle the chunks order to re-encrypt the data at random chunks, instead of a linear loop (less obvious).
	size_t chunksNum = (dataLength + CHUNK_SIZE - 1) / CHUNK_SIZE; // round up to include an extra chunk for the remainder
	std::vector<size_t> chunkIndexes(chunksNum);

	for (int i = 0; i < chunksNum; i++)
		chunkIndexes[i] = i;

	std::random_device rd;
	std::mt19937 rng(rd());
	small_junk();
	std::shuffle(chunkIndexes.begin(), chunkIndexes.end(), rng); // Shuffle the chunk indexes

	junk();

	for (size_t chunkIndex : chunkIndexes) // Iterate on the chunks indexes
	{
		size_t startIdx = chunkIndex * CHUNK_SIZE;
		size_t endIdx = startIdx + CHUNK_SIZE < dataLength ? startIdx + CHUNK_SIZE : dataLength; // min(startIdx + CHUNK_SIZE, dataLength)

		double junk = not_inlined_junk_func_2(13.32f);
		for (size_t i = startIdx; i < endIdx; i++) // Iterate on the data itself
		{
			if (i == 0) continue; // Skip the first byte which is the flag byte
			// Lots of dummy code
			int dummy = (int)data[i] + (int)(dynamicKey[i % DYNAMIC_KEY_LENGTH]) * (int)i;
			dummy = dummy * dummy;
			dummy += (dataLength & 0xFF);
			if (dummy % 7 == 0)
				junk_var_5 = ((int)junk >> 8) & 0xFF;

			if ((((unsigned int)dummy >> 4) ^ 0xAF) == 0xFF19C4CC) 
				data[i] = ((data[i] ^ 0xAF) + dummy) / 3; 
			else // Always true
				data[i] = data[i] ^ (unsigned char)(BUILD_TIME_CIPHER_BYTE ^ RUNTIME_CIPHER_BYTE); // The compiler will optimize all the operations here, obfuscating the compile time cipher further.


		}
	}
	// Now data is encrypted as: data XOR dynamic_key.

	data[0] |= 0x80; // Set the highest bit in the first byte to indicate that runtime re-encryption has already happened on subsequent calls.
}

std::string decrypt_bytes(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey, size_t dummy)
{
	junk_var_2 = 5;
	std::string result = "";
	result.resize(dataLength - 2); // Allocate space in the string without the flag byte (first byte) and the null terminator (the null terminator is encrypted too)

	// Decrypt the data in random chunks of CHUNK_SIZE, not linearly
	// Important note - the decryption order will be randomized differently from the encryption order of the bytes, but it doesn't matter because each byte transformation is independent of other elements, but only its current iteration.
	size_t chunksNum = (dataLength + CHUNK_SIZE - 1) / CHUNK_SIZE; // round up for the remainder
	std::vector<size_t> chunkIndexes(chunksNum);

	for (int i = 0; i < chunksNum; i++)
		chunkIndexes[i] = i;

	std::random_device rd;
	std::mt19937 rng(rd());
	std::shuffle(chunkIndexes.begin(), chunkIndexes.end(), rng); // Shuffle the chunk indexes 
	junk_var_1 = (int)dummy ^ 0xD3;

	if (!(dummy - ((dataLength + junk_var_2) ^ 0xAF))) // Always true (junk_var_2 is initialized to 5 at the start of the func)
	{
		for (size_t chunkIndex : chunkIndexes) // Random cycles on the data
		{
			size_t startIdx = chunkIndex * CHUNK_SIZE;
			size_t endIdx = startIdx + CHUNK_SIZE < dataLength ? startIdx + CHUNK_SIZE : dataLength;

			// loop until dataLength - 1 to exclude
			// the null terminator from data (no need to add it to an std::string)
			for (size_t i = startIdx; i < endIdx && i < dataLength - 1; i++)
			{
				if (i == 0) continue; // Skip the first byte

				junk();

				result[i-1] = (char)(data[i] ^ RUNTIME_CIPHER_BYTE);

				small_junk();
			}
		}
	}
	return result;
}
