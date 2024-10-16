import base64
from Crypto.Cipher import AES
import Crypto.Random

def xor_byte_strings(input_bytes_1, input_bytes_2):
    return bytes(x ^ y for x, y in zip(input_bytes_1, input_bytes_2))

def pkcs7_pad(data, block_size):
    padding_size = block_size - len(data) % block_size
    if padding_size == 0:
        padding_size = block_size
    padding = chr(padding_size).encode() * padding_size
    return data + padding

def aes_ecb_encode(plaintext_b, key_b):
    cipher = AES.new(key_b, AES.MODE_ECB)
    return cipher.encrypt(plaintext_b)

def generate_random_key(key_length):
    return Crypto.Random.get_random_bytes(key_length)

def determine_block_size():
    data = b''
    initial_length = len(encryption_oracle(data))
    while True:
        data += b'A'
        result_length = len(encryption_oracle(data))
        if result_length != initial_length:
            break
    return result_length - initial_length

def encryption_oracle(data):
    unknown_string = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK'''
    suffix = base64.b64decode(unknown_string.encode())
    data_to_encrypt = pkcs7_pad(random_prefix + data + suffix, block_size)
    return aes_ecb_encode(data_to_encrypt, key)

def count_same_length(bytes1, bytes2):
    count = 0
    xor_result = xor_byte_strings(bytes1, bytes2)
    for i in xor_result:
        if i == 0:
            count += 1
        else:
            break
    return count

def determine_prefix_padding_size(block_size):
    data = b''
    cipher_of_pre = encryption_oracle(data)
    data += b'A'
    init_block_num = count_same_length(cipher_of_pre, encryption_oracle(data)) // block_size
    
    while True:
        data += b'A'
        cipher_of_A = encryption_oracle(data)
        same_block_num = count_same_length(cipher_of_pre, cipher_of_A) // block_size
        if same_block_num != init_block_num:
            break
        cipher_of_pre = cipher_of_A
            
    return same_block_num * block_size - len(data) + 1

def decrypt_byte(block_size, prefix_padding_size, decrypted_message):
    probe_length = block_size - ((1 + len(decrypted_message) + prefix_padding_size) % block_size)
    testing_length = prefix_padding_size + probe_length + (len(decrypted_message) + 1)
    byte_dict = {}
    
    for byte in range(256):
        test_data = b"A" * probe_length + decrypted_message + bytes([byte])
        test_ciphertext = encryption_oracle(test_data)
        byte_dict[test_ciphertext[:testing_length]] = byte
        
    comparison_ciphertext = encryption_oracle(b"A" * probe_length)[:testing_length]
    return bytes([byte_dict.get(comparison_ciphertext, 0)])

def main():
    assume_block_size = determine_block_size()
    prefix_padding_size = determine_prefix_padding_size(assume_block_size)
    
    length_of_encrypted_unknown_string = len(encryption_oracle(b''))
    discovered_string = b''
    
    for _ in range(length_of_encrypted_unknown_string):
        discovered_string += decrypt_byte(assume_block_size, prefix_padding_size, discovered_string)
    
    print(discovered_string.decode())

if __name__ == '__main__':
    block_size = AES.block_size
    key = generate_random_key(16)
    random_prefix = generate_random_key(Crypto.Random.get_random_bytes(1)[0] % 32 + 1)  # Generate a random prefix of length 1 to 32
    main()
