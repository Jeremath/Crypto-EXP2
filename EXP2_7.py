def valid_padding(paddedMsg, block_size):
    if len(paddedMsg) % block_size != 0:
        return False
    last_byte = paddedMsg[-1] 
    if last_byte >= block_size:
        return False
    padValue = bytes([last_byte]) * last_byte
    if paddedMsg[-last_byte:] != padValue:
        return False
    if not paddedMsg[:-last_byte].decode('ascii').isprintable():
        return False
    return True

def remove_padding(paddedMsg, block_size):
    try:
        if not valid_padding(paddedMsg, block_size):
            raise ValueError
    except ValueError:
        print(f"{ paddedMsg } has invalid PKCS#7 padding.")
        return
    
    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    print(f"Before padding removal: { paddedMsg }")
    print(f"After padding removal: { unpadded }")

def main():
    block_size = 16
    paddedMsg = b"ICE ICE BABY\x04\x04\x04\x04"
    remove_padding(paddedMsg, block_size)
    paddedMsg = b"ICE ICE BABY\x05\x05\x05\x05" 
    remove_padding(paddedMsg, block_size)
    paddedMsg = b"ICE ICE BABY\x01\x02\x03\x04"
    remove_padding(paddedMsg, block_size)


if __name__ == "__main__":
    main()
