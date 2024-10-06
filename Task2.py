from Crypto.Cipher import AES
import base64
import random
import string
import urllib.parse

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

def custom_url_encode(string, encode_chars):
	encode_set = set(encode_chars)
	encoded_string = ''
	for char in string:
		if char in encode_set:
			encoded_string += urllib.parse.quote(char)
		else:
			encoded_string += char 
	return encoded_string 

def custom_url_decode(encoded_string, decode_chars):
	decode_set = set(decode_chars)
	decoded_string = ''
	i=0
	while i<len(encoded_string):
		char = encoded_string[i]
		if char == '%':
			if i+2 < len(encoded_string):
				hex_value = encoded_string[i+1:i+3]
				try:
					decoded_char = chr(int(hex_value, 16))
					if decoded_char in decode_set:
						decoded_string += decoded_char
						i+=3
						continue
				except ValueError:
					pass
		decoded_string += char
		i+=1
	return decoded_string

def verify(string, key, iv):
	decryptedBytes = cbc_decrypt(string, key, iv)
	print("Decrypted Bytes : ", decryptedBytes)
	try:
		decryptedString = decryptedBytes.decode('utf-8')
	except UnicodeDecodeError as e:
		print("Failed to decode:", e)
		return False
	print(decryptedString)
	if ";admin=true;" in decryptedString:
		return True
	else:
		return False

	
def submit(key, iv):
	#Type '' 
	user_provided_string = input("Enter arbitrary string : ")
	plaintext = "userid=456;userdata=" 
	plaintext += custom_url_encode(user_provided_string, [';', '=']) 
	plaintext += ";session-id=31337"
	#userid=456;userdata=;session-id=31337
	print(plaintext)
	encodedPlainText = plaintext.encode('utf-8')
	ciphertext = cbc_encrypt(encodedPlainText, key, iv)
	checker = cbc_decrypt(ciphertext, key, iv)
	if(checker != encodedPlainText):
		raise ValueError('CBC Encryption Failed')
	return ciphertext

# def cbc_encrypt(plaintext, key, initializationVector):
# 	data = pad(plaintext)
# 	cipher = AES.new(key, AES.MODE_ECB)
# 	ciphertext = b""
# 	prev_block = initializationVector
# 	for i in range(0, len(data), BLOCKSIZE):
# 		block = data[i : i+BLOCKSIZE]
# 		xored = bytes(xorFunction(block, prev_block))
# 		encrypted_block = cipher.encrypt(xored)
# 		ciphertext += encrypted_block
# 		prev_block = encrypted_block
# 	return ciphertext

# def pad(plaintextMessage):
# 	padSize = BLOCKSIZE - (len(plaintextMessage) % BLOCKSIZE)
# 	padding = bytes([padSize] * padSize)
# 	data = plaintextMessage + padding 
# 	return data

def breakCBC(ciphertext):
    # Convert ciphertext to a mutable bytearray for modification
    print(len(ciphertext))
    split_bytes = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    print(split_bytes)

    modified_ciphertext = bytearray(ciphertext)

    offset = len(split_bytes) - 1
    target = b'admin=true;'
    target = pad(target)
    prev_block = split_bytes[offset]
    xored = bytes(xorFunction(target, prev_block))


    modified_ciphertext.append()

    # Offset where 'userdata=' starts in the plaintext
    # userdata_offset = 15  # Length of 'userid=456;'
    
    # # Create target string we want to inject
    # target = b'admin=true;'
    
    # # Length of the target string
    # target_length = len(target)
    
    # # Calculate the length of the original ciphertext's userdata section
    # # Here, we are just modifying the first block of data to achieve our goal
    # for i in range(target_length):
    #     modified_ciphertext[userdata_offset + i] ^= (ciphertext[userdata_offset + i] ^ target[i])

    # return bytes(modified_ciphertext)


def visualize_blocks(plaintext):
    """Visualize how the plaintext splits into 16-byte blocks."""
    blocks = split_blocks(plaintext)
    for i, block in enumerate(blocks):
        print(f"Block {i + 1}: {block} ({block.decode(errors='replace')})")

def split_blocks(data):
    """Split the given data into blocks of size BLOCKSIZE (16 bytes)."""
    return [data[i:i + BLOCKSIZE] for i in range(0, len(data), BLOCKSIZE)]

def flip_bit(ciphertext, block_idx, byte_offset, bit_index):
    # Convert ciphertext to a mutable bytearray
    mutable_ciphertext = bytearray(ciphertext)

    # Get the position in the ciphertext we want to flip
    position = block_idx * BLOCKSIZE + byte_offset

    # Flip the specified bit
    mutable_ciphertext[position] ^= (1 << bit_index)

    return bytes(mutable_ciphertext)

def main():
	random.seed(42)
	key = generate_random_key(16)
	iv = generate_random_iv(16)

	string = submit(key, iv)
	# Visualize the blocks of the URL-encoded plaintext before encryption
	print("Plaintext blocks before encryption:")
	urlEncodedPlainText = "userid%3D456%3Buserdata=foo%3Bsession-id%3D31337".encode('utf-8')
	visualize_blocks(urlEncodedPlainText)

	print("\nCiphertext:")
	print(string)

	# Visualize the ciphertext blocks (optional)
	print("\nCiphertext blocks:")
	visualize_blocks(string)

	# Verify admin access with original and modified ciphertext
	print("\nAdmin access granted:", verify(string, key, iv))

	# Modify the ciphertext (flip bits in block 1 to affect block 2)
	modified_ciphertext = flip_bit(string, 1, 2, 0)
	print("\nAdmin access granted after bit flip:", verify(modified_ciphertext, key, iv))

	# Decrypt the modified ciphertext
	decrypted = cbc_decrypt(modified_ciphertext, key, iv)
	print("Decrypted modified ciphertext:", decrypted)

if __name__ == '__main__':
	main()

