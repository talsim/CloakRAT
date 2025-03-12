import os
import secrets

HEADER_NAME = 'encrypted_strings_autogen.h'
SOURCE_NAME = 'encrypted_strings_autogen.cpp'
DIR = 'Shared/'
KEY_ENTROPY = 16 # bytes
# COMPILE_TIME_CIPHER_BYTE = ((i % 4 | ((i * 9) / 2 + COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()] & ((i/2)>>3) * i - COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()]) << i) ^ 0x9F) // Add random ops to make the XOR obfuscation more unique



# Add or modify strings here.
strings_to_encrypt = {
    'str_ip': '127.0.0.1',
    'str_cmd': 'cmd.exe /C',
    'str_kernel32': 'kernel32.dll',
}

def keygen() -> list[int]:
    key = []
    for _ in range(KEY_ENTROPY):
        key.append(secrets.randbelow(256))
    return key
    

def xor_encrypt(string_plaintext: str) -> list[int]:
    # loop through the plaintext and just xor it with the cipher
    pass

def to_c_array(variable_name: str, buffer: list[int]) -> str:
    pass

def to_extern_decl(variable_name: str) -> str:
    pass
    

def main():
    key = keygen()
    # create the files.
    # loop through the strings_to_encrypt dict
    

if __name__ == '__main__':
        main()
