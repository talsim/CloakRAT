#pragma once

#include <iostream>
#include <array>
#include <random>
#include "junk_codes.h"
#include "encrypted_strings_autogen.h"

#define DYNAMIC_KEY_LENGTH 16
//#define BUILD_TIME_CIPHER_BYTE (char)((i % 4 | ((i * 9) / 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << i) ^ 0x9F) // Add random ops to make the XOR obfuscation more unique

//template<size_t N>
//constexpr std::array<uint8_t, N> compile_time_encrypt(const char(&str)[N]); // BAD - doesn't always run on compile-time (resulting in plaintext strings in the binary) cuz "it is up to the complier to decide" blah blah blah.
std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key();
void runtime_reencryption(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
std::string xor_transform(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
void wipeStr(std::string& str);

// 16 byte compile-time XOR key
static std::array<uint8_t, DYNAMIC_KEY_LENGTH> GLOBAL_RUNTIME_KEY = generate_runtime_key(); // static runtime key per translation unit

//template<size_t N>
//constexpr std::array<uint8_t, N> compile_time_encrypt(const char (&str)[N] /* Important syntax for constexpr - pass the arr by reference to avoid decay to pointer*/)
//{
//	std::array<uint8_t, N> encryptedArray = {};
//	for (int i = 0; i < N; i++) // Note that we encrypt the null terminator as well
//		encryptedArray[i] = str[i] ^ BUILD_TIME_CIPHER_BYTE; // Avoid typical XOR obfuscation, to not get detected easily
//	return encryptedArray;
//}

// A small helper - Re-encrypts with the global key, decrypts and returns the string
template<size_t N>
inline std::string string_encrypt(const char (&str)[N])
{
	auto arr = compile_time_encrypt(str); // Encrypt at compile time.
	runtime_reencryption(arr.data(), arr.size(), GLOBAL_RUNTIME_KEY); // Re-encrypt at runtime again.
	return xor_transform(arr.data(), arr.size(), GLOBAL_RUNTIME_KEY); // Decrypt the data by applying XOR again to cancel the re-encryption.
}

// Another small helper - Re-encrypts with the provided runtimeKey, decrypts and returns the string
template<size_t N>
inline std::string string_encrypt(const char(&str)[N], std::array<uint8_t, DYNAMIC_KEY_LENGTH> runtimeKey)
{
	auto arr = compile_time_encrypt(str);
	runtime_reencryption(arr.data(), arr.size(), runtimeKey);
	return xor_transform(arr.data(), arr.size(), runtimeKey);
}