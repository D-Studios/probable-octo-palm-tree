from Crypto.Cipher import AES
import base64
import random
import string

LAST_BYTE = -1
MINIMUM_PAD_SIZE = 1
LAST_INDEX = -1
SECOND_LAST_BYTE = -2
WRONG_PADDING_NUMBER = 255
BLOCKSIZE = 16


def xorFunction(input_bytes, key_bytes):
    j=0 
    last_index = len(key_bytes)-1
    bytes_list = []
    for i in range(0, len(input_bytes)):
        if j>last_index:
            j=0
        bytes_list.append(input_bytes[i] ^ key_bytes[j])
        j+=1
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
	if data_length%BLOCKSIZE != 0:
		raise ValueError("Pad size is not multiple of blocksize.")
	if padSize < MINIMUM_PAD_SIZE or padSize > data_length:
		raise ValueError("Invalid padding size")
	i = 0
	while True:
		if i>=padSize:
			break
		pad_byte = data[pad_index]
		if pad_byte != padSize:
			raise ValueError("Invalid padding byte")
		i+=1
		pad_index-=1
	return data[0:data_length-padSize]

def cbc_encrypt(plaintext, key, initializationVector):
	data = pad(plaintext)
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = b""
	prev_block = initializationVector
	for i in range(0, len(data), BLOCKSIZE):
		block = data[i : i+BLOCKSIZE]
		xored = bytes(xorFunction(block, prev_block))
		encrypted_block = cipher.encrypt(xored)
		ciphertext += encrypted_block
		prev_block = encrypted_block
	return ciphertext

def cbc_decrypt(ciphertext, key, initializationVector):
	cipher = AES.new(key, AES.MODE_ECB)
	if len(ciphertext)%BLOCKSIZE != 0:
		raise ValueError("Decrypted ciphertext not multiple of block size.")
	
	decryptedCipherText = b""
	prev_block = initializationVector

	for i in range(0, len(ciphertext), BLOCKSIZE):
		block = ciphertext[i : i+BLOCKSIZE]
		decrypted_block = cipher.decrypt(block)
		decryptedCipherText += bytes(xorFunction(decrypted_block, prev_block))
		prev_block = block
	plaintext = unpad(decryptedCipherText)
	return plaintext

def generate_random_key(length) :
	characters = string.ascii_letters + string.digits
	random_key = ''.join(random.choice(characters) for i in range(length))
	return random_key.encode('utf-8')

def generate_random_iv(length):
	random_iv = bytes(random.getrandbits(8) for i in range(length))
	return random_iv
	

def main():
	plainTextFile = input("Enter plaintext file name : ")
	key = generate_random_key(16)
	random_iv = generate_random_iv(16)
	outputFile = input("Enter output filename: ")
	plaintext = ""

	with open(plainTextFile) as file:
		plaintext = file.read()

	plaintext = plaintext.encode('utf-8')
	ciphertext = cbc_encrypt(plaintext, key, random_iv)
	checker = cbc_decrypt(ciphertext, key, random_iv)

	if(checker != plaintext):
		raise ValueError("Something is wrong with encryption/decryption.")
		return

	with open(outputFile, 'w') as file:
		file.write(f"{ciphertext}")

if __name__ == '__main__':
	main()

