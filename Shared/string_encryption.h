#pragma once

#include <iostream>
#include <array>
#include <random>
#include "junk_codes.h"

#define DYNAMIC_KEY_LENGTH 16
#define COMPILE_TIME_CIPHER_BYTE (char)((i % 4 | ((i * 9) / 2 + COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()] & ((i/2)>>3) * i - COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()]) << i) ^ 0x9F) // Add random ops to make the XOR obfuscation more unique

template<size_t N>
constexpr std::array<char, N> compile_time_encrypt(const char(&str)[N]);
std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key();
void runtime_reencryption(char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
std::string xor_transform(char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
void wipeStr(std::string& str);

// 16 byte compile-time XOR key
constexpr std::array<uint8_t, 16> COMPILE_TIME_KEY = { 0xF1, 0x0A, 0x3E, 0xCC, 0xE9, 0x11, 0xF0, 0x7C, 0xE9, 0xB3, 0x06, 0x4B, 0x90, 0xDA, 0xFF, 0x55 };
static std::array<uint8_t, DYNAMIC_KEY_LENGTH> GLOBAL_RUNTIME_KEY = generate_runtime_key(); // static runtime key per translation unit

template<size_t N>
constexpr std::array<char, N> compile_time_encrypt(const char (&str)[N] /* Important syntax for constexpr - pass the arr by reference to avoid decay to pointer*/)
{
	std::array<char, N> encryptedArray = {};
	for (int i = 0; i < N; i++) // Note that we encrypt the null terminator as well
		encryptedArray[i] = str[i] ^ COMPILE_TIME_CIPHER_BYTE; // Avoid typical XOR obfuscation, to not get detected easily
	return encryptedArray;
}

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