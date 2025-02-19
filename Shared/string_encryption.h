#pragma once

#include <iostream>
#include <array>
#include <random>
#include "junk_codes.h"

#define DYNAMIC_KEY_LENGTH 16
#define COMPILE_TIME_CIPHER (i % 4 | ((i * 9) / 2 + COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()] & i * i - COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()]) << i) // Add random ops to make the XOR obfuscation more unique

std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key();

// 16 byte compile-time XOR key
constexpr std::array<uint8_t, 16> COMPILE_TIME_KEY = { 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };

template<size_t N>
constexpr std::array<char, N> compile_time_encrypt(const char (&str)[N] /* Important syntax for constexpr - pass the arr by reference to avoid decay to pointer*/)
{
	std::array<char, N> encryptedArray = {}; 
	for (int i = 0; i < N; i++)
		encryptedArray[i] = str[i] ^ (char)COMPILE_TIME_CIPHER; // Avoid typical XOR obfuscation, to not get detected easily
	return encryptedArray;
}
