#pragma once

#include <iostream>
#include <array>
#include <random>
#include "junk_codes.h"

#define RUNTIME_KEY_LENGTH 16

std::array<uint8_t, RUNTIME_KEY_LENGTH> generate_dynamic_key();

// 16 byte compile-time XOR key
constexpr std::array<uint8_t, 16> COMPILE_TIME_KEY = { 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };

template<size_t N>
constexpr std::array<char, N> compile_time_encrypt(const char (&str)[N])
{
	std::array<char, N> encryptedArray = {}; 
	for (int i = 0; i < N; i++)
		encryptedArray[i] = str[i] ^ (char)(i % 4 | ((i * 9) / 2 + COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()] & i * i - COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()]) << i); // using the key to perform weird operations to avoid typical XOR obfuscation signatures
	return encryptedArray;
}