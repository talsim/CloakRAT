import secrets

HEADER_NAME = 'encrypted_strings_autogen.h'
SOURCE_NAME = 'encrypted_strings_autogen.cpp'
DIR = 'Shared'
KEY_ENTROPY = 16 # bytes
# COMPILE_TIME_CIPHER_BYTE = ((i % 4 | ((i * 9) / 2 + COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()] & ((i/2)>>3) * i - COMPILE_TIME_KEY[i % COMPILE_TIME_KEY.size()]) << i) ^ 0x9F) // Add random ops to make the XOR obfuscation more unique



# Add or modify strings here.
strings_to_encrypt = {
    'str_ip': '127.0.0.1',
    'str_cmd': 'cmd.exe /C',
    'str_dllPath': '.....................',
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
    # return in the format: "unsigned char[] var1 = { ... };"
    pass

def to_extern_decl(variable_name: str) -> str:
    # return in the format: "extern unsigned char var1[];"
    pass
    

def main():
    key = keygen()
    with open(f'{DIR}/{SOURCE_NAME}', 'w') as source_file:
        for var_name, string in strings_to_encrypt.items():
            encrypted_string_lst = xor_encrypt(string)
            encrypted_c_arr = to_c_array(var_name, encrypted_string_lst)
            source_file.write(encrypted_c_arr + '\n')
    with open(HEADER_NAME, 'w') as header_file:
        for var_name in strings_to_encrypt.keys():
            extern_decl = to_extern_decl(var_name)
            header_file.write(extern_decl + '\n')

if __name__ == '__main__':
        main()
