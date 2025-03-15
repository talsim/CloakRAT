#pragma once

#include <iostream>
#include <array>
#include <random>
#include "junk_codes.h"
#include "encrypted_strings_autogen.h"

#define DYNAMIC_KEY_LENGTH 16

std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key();
void runtime_reencryption(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
std::string xor_transform(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
void wipeStr(std::string& str);

// 16 byte compile-time XOR key
static std::array<uint8_t, DYNAMIC_KEY_LENGTH> GLOBAL_RUNTIME_KEY = generate_runtime_key(); // static runtime key per translation unit

// A small helper - Re-encrypts with the global key, decrypts and returns the string
inline std::string reencrypt_and_decrypt(unsigned char* str, size_t len)
{
	runtime_reencryption(str, len, GLOBAL_RUNTIME_KEY); // Re-encrypt at runtime again.
	return xor_transform(str, len, GLOBAL_RUNTIME_KEY); // Decrypt the data by applying XOR again to cancel the re-encryption.
}

// Another small helper - Re-encrypts with the provided runtimeKey, decrypts and returns the string
//template<size_t N>
//inline std::string reencrypt_and_decrypt(const char(&str)[N], std::array<uint8_t, DYNAMIC_KEY_LENGTH> runtimeKey)
//{
//	auto arr = compile_time_encrypt(str);
//	runtime_reencryption(arr.data(), arr.size(), runtimeKey);
//	return xor_transform(arr.data(), arr.size(), runtimeKey);
//}