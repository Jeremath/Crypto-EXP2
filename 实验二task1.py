from hashlib import sha1
from base64 import b64decode
from Crypto.Cipher import AES
from binascii import unhexlify


def calculate_parity(x):
    k = []
    binary_representation = bin(int(x, 16))[2:]

    for i in range(0, len(binary_representation), 8):
        byte = binary_representation[i:i + 7]
        parity_bit = '1' if byte.count('1') % 2 == 0 else '0'
        k.append(byte)
        k.append(parity_bit)

    return hex(int(''.join(k), 2))[2:] 


def generate_key(mrz):
    keyseed = sha1(mrz.encode()).hexdigest()[:32] + '00000001'
    key = sha1(unhexlify(keyseed)).hexdigest()
    
    key_a = calculate_parity(key[:16])
    key_b = calculate_parity(key[16:32])
    
    return unhexlify(key_a + key_b)  


def main():
    passport = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'
    encoded_ciphertext = b'''9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMa
                            zJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'''
    ciphertext = b64decode(encoded_ciphertext)

    mrz_section = passport[21:27]
    weights = [7, 3, 1]
    check_digit = sum(int(mrz_section[i]) * weights[i % 3] for i in range(len(mrz_section))) % 10
    passport = passport[:27] + str(check_digit) + passport[28:]

    mrz = passport[:10] + passport[13:20] + passport[21:28]
    print(f'Machine Readable Zone (MRZ): {mrz}')

    key = generate_key(mrz)
    print(f'AES Key: {key.hex()}')

    aes = AES.new(key, mode=AES.MODE_CBC, iv=b'\x00' * 16)
    decrypted_data = aes.decrypt(ciphertext)
    print(f'Decrypted Data: {decrypted_data}')


if __name__ == "__main__":
    main()
