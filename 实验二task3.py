import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PREPEND_STR = b"comment1=cooking%20MCs;userdata="
APPEND_STR = b";comment2=%20like%20a%20pound%20of%20bacon"
TARGET_PARAM = b";admin=true;"
KEY_SIZE = 16

random_key = os.urandom(KEY_SIZE)
random_IV = os.urandom(KEY_SIZE)

def encrypt_AES_CBC(plaintext: bytes, iv: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    return aes.encrypt(padded_data)

def decrypt_AES_CBC(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def pad_PKCS7(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad_PKCS7(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding.")
    return data[:-padding_len]

# Encryptor function to pad and encrypt data with AES-CBC
def custom_encrypt(user_input: bytes, iv: bytes, key: bytes) -> bytes:
    data_to_encrypt = (PREPEND_STR + user_input + APPEND_STR).replace(b';', b'%3B').replace(b'=', b'%3D')
    return encrypt_AES_CBC(pad_PKCS7(data_to_encrypt, len(key)), iv, key)

# Decryptor function to check for ";admin=true;" after decryption
def custom_decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> bool:
    decrypted = unpad_PKCS7(decrypt_AES_CBC(ciphertext, iv, key))
    return b";admin=true;" in decrypted

# Bit-flipping attack to manipulate ciphertext
def perform_bit_flipping(target: bytes, block_size: int, encrypt_func: callable) -> bytes:
    initial_len = len(encrypt_func(b'', random_IV, random_key))
    prefix_len = len(os.path.commonprefix([encrypt_func(b'A'*4, random_IV, random_key), encrypt_func(b'', random_IV, random_key)]))
    print(prefix_len)
    random_blocks = 0
    for i in range(initial_len // block_size):
        if prefix_len < i * block_size:
            random_blocks = i
            break
    print(random_blocks)
    padding_len = 0
    base_cipher = encrypt_func(b'', random_IV, random_key)
    for i in range(1, block_size):
        new_cipher = encrypt_func(b'A' * i, random_IV, random_key)
        new_prefix_len = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_len > prefix_len:
            padding_len = i - 1
            break
        base_cipher = new_cipher
    print(padding_len)
    input_text = b'A' * padding_len + b"dytdytdytdyt"
    ciphertext = encrypt_func(input_text, random_IV, random_key)

    modified_bytes = b""
    for i in range(len(target)):
        modified_byte = (ciphertext[i + (random_blocks - 1) * block_size] ^ (input_text[i + padding_len] ^ target[i])).to_bytes(1, "big")
        modified_bytes += modified_byte

    modified_ciphertext = ciphertext[:(random_blocks - 1) * block_size] + modified_bytes + ciphertext[(random_blocks - 1) * block_size + len(modified_bytes):]
    
    return modified_ciphertext

modified_ciphertext = perform_bit_flipping(TARGET_PARAM, KEY_SIZE, custom_encrypt)
print(decrypt_AES_CBC(modified_ciphertext, random_IV, random_key))
