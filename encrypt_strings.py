import secrets

HEADER_NAME = 'encrypted_strings_autogen.h'
SOURCE_NAME = 'encrypted_strings_autogen.cpp'
DIR = 'Shared'
KEY_ENTROPY = 16 # bytes
HEADER_XOR_KEY_VARIABLE_NAME = 'BUILD_TIME_KEY'
HEADER_XOR_CIPHER_VARIABLE_NAME = 'BUILD_TIME_CIPHER_BYTE'


# Add or modify strings here.
strings_to_encrypt = {
    'str_ip': '127.0.0.1',
    'str_cmd': 'cmd.exe /C',
    'str_dllPath': '.....................',
    'str_kernel32': 'kernel32.dll',
}

def gen_key() -> list[int]:
    key = []
    for _ in range(KEY_ENTROPY):
        key.append(secrets.randbelow(256))
    return key

def get_random_op() -> str:
    return secrets.choice(['+', '-', '*'])

def xor_encrypt(string_plaintext: str, key: list[int], cipher: str) -> list[int]:
    # loop through the plaintext and just xor it with the cipher
    encrypted_bytes = []
    data = string_plaintext.encode('utf-8') + b'\x00' # add the null terminator because this we treat the string as a C-style string 

    for i, byte in enumerate(data):
        
        encrypted_bytes.append((byte ^ eval(cipher)) & 0xFF)
    
    return encrypted_bytes
    

def to_c_array(variable_name: str, buffer: list[int]) -> str:
    # return in the format: "unsigned char variable_name[] = { ...buffer };"
    elems = ', '.join(str(b) for b in buffer)
    return f"unsigned char {variable_name}[] = {{ {elems} }};" 
    

def to_extern_decl(variable_name: str) -> str:
    # return in the format: "extern unsigned char variable_name[];"
    return f"extern unsigned char {variable_name}[];"
    

def main():
    key = gen_key()

    rand_op1 = get_random_op()
    rand_op2 = get_random_op()
    rand_op3 = get_random_op()
    rand_xor_value = secrets.randbelow(256)
    
    # BE CAREFUL TO EDIT VARIABLE NAMES HERE, BECAUSE THIS IS GOING TO BE PROCESSED BY eval()
    byte_chiper = f"((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + key[i % len(key)] & ((i//2)>>3) * i {rand_op3} key[i % len(key)]) << i) ^ {rand_xor_value})" # randomize the cipher each run
    
    # Generate the Source file 
    with open(f'{DIR}/{SOURCE_NAME}', 'w') as source_file:
        source_file.write(f'#include \"{HEADER_NAME}\"\n\n')
        
        for var_name, string in strings_to_encrypt.items():
            encrypted_string_lst = xor_encrypt(string, key, byte_chiper)
            encrypted_c_arr = to_c_array(var_name, encrypted_string_lst)
            source_file.write(encrypted_c_arr + '\n')  # Write the encrypted string array
            source_file.write(f'size_t {var_name}_len = sizeof({var_name});\n')  # Write the length of the array
    
    # Generate the Header file
    with open(f'{DIR}/{HEADER_NAME}', 'w') as header_file:
        
        c_style_byte_cipher = f"(unsigned char)((i % 4 | ((i {rand_op1} 9) {rand_op2} 2 + {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()] & ((i/2)>>3) * i {rand_op3} {HEADER_XOR_KEY_VARIABLE_NAME}[i % {HEADER_XOR_KEY_VARIABLE_NAME}.size()]) << i) ^ {rand_xor_value})"
        
        header_file.write('#pragma once\n\n')
        header_file.write('#include <array>\n\n')
        header_file.write(f'#define {HEADER_XOR_CIPHER_VARIABLE_NAME} {c_style_byte_cipher}\n')
        header_file.write(f'std::array<uint8_t, {KEY_ENTROPY}> {HEADER_XOR_KEY_VARIABLE_NAME} = {{ {', '.join(str(b) for b in key)} }};\n\n')
        
        for var_name in strings_to_encrypt.keys():
            extern_decl = to_extern_decl(var_name)
            header_file.write(extern_decl + '\n')
            header_file.write(f'extern size_t {var_name}_len;\n')

if __name__ == '__main__':
        main()
