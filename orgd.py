#import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_OFB(file_path, key_name):
  # Generate a unique nonce (lol) for each file
  iv = get_random_bytes(16)
  key = get_random_bytes(32)
  
  # AES block size is fixed at 16 bytes
  block_size = 16
  key = key[:block_size] #slice the key to the correct length

  with open(file_path, "rb") as in_file:
      plaintext = in_file.read()
  
  # Pad the plaintext to a multiple of the block size
  padding_length = block_size - (len(plaintext) % block_size)
  plaintext += bytes([padding_length]) * padding_length
  
  # Create a new AES cipher with the given key and IV
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # Encrypt the plaintext
  ciphertext = cipher.encrypt(plaintext)

  with open(key_name, "wb") as key_file:
    key_file.write(key)
  
  with open(file_path, "wb") as out_file:
    out_file.write(iv)
    out_file.write(ciphertext)



def decrypt_OFB(file_path, key_name):
  # AES block size is fixed at 16 bytes
  block_size = 16
  # key = get_random_bytes(32)[:block_size]

  with open(key_name, "rb") as key_file:
    key = key_file.read()

  # Open the input file in binary mode
  with open(file_path, "rb") as in_file:
    # Read the IV from the input file
    iv = in_file.read(16)
    # Read the ciphertext from the input file
    ciphertext = in_file.read()
      
  # Create a new AES cipher with the given key and IV
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # Decrypt the ciphertext
  plaintext = cipher.decrypt(ciphertext)
  
  # Remove the padding from the plaintext
  padding_length = plaintext[-1]
  plaintext = plaintext[:-padding_length]
  
  # Open the output file in binary mode
  with open(file_path, "wb") as out_file:
      # Write the plaintext to the output file
      out_file.write(plaintext)



def encrypt_EAX(file_path, key_name):
  # Generate a unique nonce for each file
  nonce = get_random_bytes(16)
  
  # AES block size is fixed at 16 bytes
  block_size = 16
  key = key[:block_size]
  
  # Open the input file in binary mode
  with open(file_path, "rb") as in_file:
    # Read the entire file into memory
    plaintext = in_file.read()
  
  # Pad the plaintext to a multiple of the block size
  padding_length = block_size - (len(plaintext) % block_size)
  plaintext += bytes([padding_length]) * padding_length
  
  # Create a new AES cipher with the given key and nonce
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  
  # Encrypt the plaintext
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)
  
  with open(key_name, "wb") as key_file:
    key_file.write(key)

  # Open the output file in binary mode
  with open(file_path, "wb") as out_file:
    # Write the nonce to the output file
    out_file.write(nonce)
    # Write the tag to the output file
    out_file.write(tag)
    # Write the ciphertext to the output file
    out_file.write(ciphertext)



def decrypt_EAX(file_path, key_name):
  # AES block size is fixed at 16 bytes
  block_size = 16
  #key = key[:block_size]

  with open(key_name, "rb") as key_file:
    key = key_file.read()
  
  # Open the input file in binary mode
  with open(file_path, "rb") as in_file:
    # Read the nonce from the input file
    nonce = in_file.read(16)
    # Read the tag from the input file
    tag = in_file.read(16)
    # Read the ciphertext from the input file
    ciphertext = in_file.read()
      
  # Create a new AES cipher with the given key and nonce
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  
  # Decrypt the ciphertext
  plaintext = cipher.decrypt_and_verify(ciphertext, tag)
  
  # Remove the padding from the plaintext
  padding_length = plaintext[-1]
  plaintext = plaintext[:-padding_length]
  
  # Open the output file in binary mode
  with open(file_path, "wb") as out_file:
    # Write the plaintext to the output file
    out_file.write(plaintext)



while True:
  prompt = '''What do you want to do?
  1 -> encrypt
  2 -> decrypt
  0 -> quit
 -> '''
  promptMethod = '''Which method do you prefer?
    1 -> No authentication
    2 -> Authentication
  -> '''
  promptPath = '''Specify the file path 
  -> '''
  promptKey = '''Specify the key's file name
  ->'''

  choice = input(prompt)
  choiceMethod = input(promptMethod)
  file_path = input(promptPath)
  key_name = input(promptKey)
  if choice == '1':
    if choiceMethod == '1':
      encrypt_OFB(file_path, key_name)
    elif choiceMethod == '2':
      encrypt_EAX(file_path, key_name)
  elif choice == '2':
    if choiceMethod == '1':
      decrypt_OFB(file_path, key_name)
    elif choiceMethod == '2':
      decrypt_EAX(file_path, key_name)
  elif choice == '0':
    exit()
  else:
    print('Invalid choice, please try again!')