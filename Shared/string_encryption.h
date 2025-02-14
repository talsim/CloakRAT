#pragma once

#include "iostream"
#include "array"

// 16 byte compile-time XOR key
constexpr std::array<uint8_t, 16> BASE_KEY = { 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };

template<size_t N>
constexpr std::array<char, N> compile_time_encrypt(const char (&str)[N])
{
	std::array<char, N> encryptedArray = {}; 
	for (int i = 0; i < N; i++)
	{
		encryptedArray[i] = str[i] ^ BASE_KEY[i % BASE_KEY.size()];
	}
	return encryptedArray;
}