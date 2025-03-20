#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <array>
#include "encrypted_strings_autogen.h"

#define DYNAMIC_KEY_LENGTH 16
#define string_decrypt_cstr(str, len) string_decrypt(str, len).c_str()

std::array<uint8_t, DYNAMIC_KEY_LENGTH> generate_runtime_key();
void runtime_reencryption(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);
std::string decrypt_bytes(unsigned char* data, size_t dataLength, std::array<uint8_t, DYNAMIC_KEY_LENGTH> dynamicKey);

// 16 byte compile-time XOR key
static std::array<uint8_t, DYNAMIC_KEY_LENGTH> GLOBAL_RUNTIME_KEY = generate_runtime_key(); // static runtime key per translation unit

inline void wipeStr(std::string& str)
{
	// Make sure the complier won't optimize this by ignoring it, then the string will remain in memory.
	// It just treats the address provided as a volatile pointer and zeroes all the bytes up to the size.
	SecureZeroMemory(&str[0], str.size());
	str.clear();
}

// A small helper - Re-encrypts with the global key, decrypts and returns the string
inline std::string string_decrypt(EncryptedString& str)
{
	runtime_reencryption(str.data, str.length, GLOBAL_RUNTIME_KEY); // Re-encrypt at runtime again.
	return decrypt_bytes(str.data, str.length, GLOBAL_RUNTIME_KEY); // Decrypt the data by applying XOR again to cancel the re-encryption.
	
	/*
	* after usage, wipe it. (because decrypt_bytes() returns a copy of the decrypted bytes in a new fresh std::string everytime)
	* wipeStr(RETURNED_STRING_FROM_DECRYPT_BYTES);
	*
	* typical usage of strings: Decrypt -> Use -> Wipe (or reencrypt if needed as a global variable).
	* 
	* E.g ->
	* std::string socket_string = reencrypt_and_decrypt(str_socket, str_socket_len);
	* this->sock = resolve_dynamically<socket_t>("socket", WS2_32_STR)(AF_INET, SOCK_STREAM, 0);
	* wipeStr(socket_string);
	*/
}

// Another small helper - Re-encrypts with the provided runtimeKey, decrypts and returns the string
//template<size_t N>
//inline std::string reencrypt_and_decrypt(const char(&str)[N], std::array<uint8_t, DYNAMIC_KEY_LENGTH> runtimeKey)
//{
//	auto arr = compile_time_encrypt(str);
//	runtime_reencryption(arr.data(), arr.size(), runtimeKey);
//	return xor_transform(arr.data(), arr.size(), runtimeKey);
//}