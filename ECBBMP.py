from Crypto.Cipher import AES
import random
import string

LAST_BYTE = -1
MINIMUM_PAD_SIZE = 1
LAST_INDEX = -1
SECOND_LAST_BYTE = -2
WRONG_PADDING_NUMBER = 255
BLOCKSIZE = 16


def xorFunction(input_bytes, key_bytes):
    j = 0
    last_index = len(key_bytes) - 1
    bytes_list = []
    for i in range(0, len(input_bytes)):
        if j > last_index:
            j = 0
        bytes_list.append(input_bytes[i] ^ key_bytes[j])
        j += 1
    result_bytes = bytes_list
    return result_bytes


def pad(plaintextMessage):
    padSize = BLOCKSIZE - (len(plaintextMessage) % BLOCKSIZE)
    padding = bytes([padSize] * padSize)
    data = plaintextMessage + padding
    return data


def unpad(data):
    data_length = len(data)
    last_data_index = data_length + LAST_INDEX
    pad_index = last_data_index
    padSize = data[LAST_BYTE]
    if data_length % BLOCKSIZE != 0:
        raise ValueError("Pad size is not multiple of blocksize.")
    if padSize < MINIMUM_PAD_SIZE or padSize > data_length:
        raise ValueError("Invalid padding size")
    i = 0
    while True:
        if i >= padSize:
            break
        pad_byte = data[pad_index]
        if pad_byte != padSize:
            raise ValueError("Invalid padding byte")
        i += 1
        pad_index -= 1
    return data[0:data_length - padSize]


def ecb_encrypt(plaintext, key):
    data = pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decryptedCipherText = cipher.decrypt(ciphertext)
    plaintext = unpad(decryptedCipherText)
    return plaintext


def generate_random_key(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(random.choice(characters) for i in range(length))
    return random_key.encode('utf-8')

def main():
    bmpFile = input("Enter plaintext file name : ")
    checkerFile = input("Enter in file name for the decrpytion of encryption of bmp file : ")
    key = generate_random_key(16)
    outputFile = input("Enter output filename: ")
    bmpBytes = ""

    with open(bmpFile, 'rb') as file:
        bmpBytes = file.read()

    bmpHeader = bmpBytes[0:54]
    bmpPlainText = bmpBytes[54:]
    ciphertext = ecb_encrypt(bmpPlainText, key)
    checker = ecb_decrypt(ciphertext, key)

    checker = bmpHeader + checker

    if (checker != bmpBytes):
        raise ValueError("Something is wrong with encryption/decryption.")
        return

    with open(checkerFile, 'wb') as file:
        file.write(checker)

    with open(outputFile, 'wb') as file:
        file.write(ciphertext)


if __name__ == "__main__":
    main()