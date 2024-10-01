from Crypto.Cipher import AES
import base64

LAST_BYTE = -1
MINIMUM_PAD_SIZE = 1
LAST_INDEX = -1
SECOND_LAST_BYTE = -2
WRONG_PADDING_NUMBER = 255
BLOCKSIZE = 16
KEY = "MIND ON MY MONEY".encode('utf-8')
IV = "MONEY ON MY MIND".encode('utf-8')

def base64ToBytes(base64string):
	#This decodes base64 string back to bytes. 
	
	return base64.b64decode(base64string)

def xorFunction(input_bytes, key_bytes):
    j=0 
    last_index = len(key_bytes)-1
    bytes_list = []
    for i in range(0, len(input_bytes)):
        #Looping back to beginning of key if key length < message length
        if j>last_index:
            j=0
        #XOR'ing each byte and appending it to bytes list
        bytes_list.append(input_bytes[i] ^ key_bytes[j])
        j+=1
    #Convert this to bytes.
    result_bytes = bytes_list
    return result_bytes

def pad(plaintextMessage):
	#Calculate number of padding bytes needed.
	padSize = BLOCKSIZE - (len(plaintextMessage) % BLOCKSIZE)
	#Create bytes for padding, with each byte indicating number of padding bytes added.
	#e.g. 1 byte will just be 1, 2 bytes will be 2 2, 3 bytes will be 3 3 3
	padding = bytes([padSize] * padSize)

	#Constructed message is bytes of plaintext appended with bytes of padding
	data = plaintextMessage + padding 

	#Return the bytes of the constructed message
	return data

def unpad(data):
	data_length = len(data)
	last_data_index = data_length + LAST_INDEX
	pad_index = last_data_index
	#Get last byte, which is guaranteed to represent padding size (if there is padding).
	padSize = data[LAST_BYTE]
	if data_length%BLOCKSIZE != 0:
		raise ValueError("Pad size is not multiple of blocksize.")
	#Padding size = last byte. If the padding size is less than the minimum pad size (which is 1)
	#or greater than the length of the message, something is wrong.
	if padSize < MINIMUM_PAD_SIZE or padSize > data_length:
		raise ValueError("Invalid padding size")
	i = 0
	while True:
		if i>=padSize:
			break
		pad_byte = data[pad_index]
		#If padding byte not equal to size of padding, return error.
		if pad_byte != padSize:
			raise ValueError("Invalid padding byte")
		i+=1
		pad_index-=1
	#Return data without its padding.
	return data[0:data_length-padSize]

# cbc_encrypt(), that takes in an arbitrary-length plaintext, a key, and an initialization vector (IV)
def cbc_encrypt(plaintext, key, initializationVector):
	#pads the message to a multiple of the block size (using your padding scheme from Task I)
	data = pad(plaintext)
	#encrypts data and returns the resulting ciphertext. 

	#Manually doing CBC mode starting from ECB mode.
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = b""
	prev_block = initializationVector
	#For each block, concatening the encryption of block xored with previous block.
	for i in range(0, len(data), BLOCKSIZE):
		block = data[i : i+BLOCKSIZE]
		xored = bytes(xorFunction(block, prev_block))
		encrypted_block = cipher.encrypt(xored)
		ciphertext += encrypted_block
		prev_block = encrypted_block
	return ciphertext

#The second function, cbc_decrypt(), should take in a ciphertext, a key, and an IV.
def cbc_decrypt(ciphertext, key, initializationVector):
	#Manually doing CBC mode starting from ECB mode.
	cipher = AES.new(key, AES.MODE_ECB)
	#cbc_decrypt() should return an error (or throw an exception) 
	#if either the ciphertext is not a multiple of the block size 
	#or if the un-padding function returns an error.
	
	if len(ciphertext)%BLOCKSIZE != 0:
		raise ValueError("Decrypted ciphertext not multiple of block size.")
	
	decryptedCipherText = b""
	prev_block = initializationVector

	#For each block, concatening the decryption of current block and past block. 
	for i in range(0, len(ciphertext), BLOCKSIZE):
		block = ciphertext[i : i+BLOCKSIZE]
		decrypted_block = cipher.decrypt(block)
		decryptedCipherText += bytes(xorFunction(decrypted_block, prev_block))
		prev_block = block
	#remove the padding and return the resulting plaintext.
	plaintext = unpad(decryptedCipherText)
	return plaintext
	

def main():
	with open('Lab2.TaskIII.A.txt') as file:
		file_contents = file.read()

	line_files = base64ToBytes(file_contents)
	print(line_files)
	print("-------------------------------------")
	line_files = cbc_decrypt(line_files, KEY, IV)
	print(line_files)
	print("-------------------------------------")
	line_files = cbc_encrypt(line_files, KEY, IV)
	print(line_files)
	print("------------------------------------")

if __name__ == '__main__':
	main()

