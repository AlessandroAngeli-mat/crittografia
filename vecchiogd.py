from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class CryptoError(Exception):
    '''An error has occured during the encryption/decryption process'''
class MenuError(Exception):
    '''An error has occured during the selection'''


def read_key(path):
    with open(path, "r") as key_file:
        key = key_file.read()
        key = bytes(key[2:len(key)-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
    return key



# function that encrypts without authentication
# - file_path is given by the user
# - key_path is also given by the user
# - it writes the key to the file asked to the user
# - it writes both the initialization vector and the ciphertext to the file asked to the user
def encrypt_no_auth(file_path, key_path):
  # generate a unique nonce and key, both 16 bytes long
  block_size = 16
  iv = get_random_bytes(block_size)
  key = get_random_bytes(block_size)
  
  # read from file
  with open(file_path, "rb") as in_file:
      plaintext = in_file.read()
  
  # make sure the plaintext's lenght is a multiple of the block size by padding if needed
  padding_length = block_size - (len(plaintext) % block_size)
  plaintext += bytes([padding_length]) * padding_length
  
  # generate a new AES cipher with the given key and initialization vector
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # encrypt the plaintext
  ciphertext = cipher.encrypt(plaintext)

  # write the key to the file
  with open(key_path, "w") as key_file:
    key_file.write(str(key))
  
  # write the iv and the ciphertext to the file
  with open(file_path, "wb") as out_file:
    out_file.write(iv)
    out_file.write(ciphertext)


# function that decrypts without authentication
# - file_path is given by the user
# - key_path is also given by the user
def decrypt_no_auth(file_path, key_path):

  with open(key_path, "r") as key_file:
    key = key_file.read()
    key = bytes(key[2:len(key)-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')

  with open(file_path, "rb") as in_file:
    # read the initialization vector, which was set at 16 bytes, then read the rest, which is the ciphertext
    iv = in_file.read(16)
    ciphertext = in_file.read()
      
  # generate a new AES cipher with the given key and initialization vector
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # decrypt the ciphertext
  plaintext = cipher.decrypt(ciphertext)
  
  # remove the padding from the original
  padding_length = plaintext[-1]
  plaintext = plaintext[:-padding_length]

  # convert the plaintext from bytes to string
  plaintext = plaintext.decode('utf-8')

  print(f'The original was: {plaintext}')

  with open(file_path, "w") as out_file:
      out_file.write(plaintext)



def encrypt_auth(file_path, key_path):
  # Generate a unique nonce for each file
  block_size = 16
  nonce = get_random_bytes(block_size)
  key = get_random_bytes(block_size)

  
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
  
  with open(key_path, "w") as key_file:
    key_file.write(str(key))

  # Open the output file in binary mode
  with open(file_path, "wb") as out_file:
    # Write the nonce to the output file
    out_file.write(nonce)
    # Write the tag to the output file
    out_file.write(tag)
    # Write the ciphertext to the output file
    out_file.write(ciphertext)



def decrypt_auth(file_path, key_path):

  with open(key_path, "r") as key_file:
    key = key_file.read()
    key = bytes(key[2:len(key)-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
  
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
  print(plaintext)
  
  # convert the plaintext from bytes to string
  plaintext = plaintext.decode('utf-8')
  print(f'decr: {plaintext}')
  
  # Open the output file in binary mode
  with open(file_path, "w") as out_file:
    # Write the plaintext to the output file
    out_file.write(plaintext)


if __name__ == '__main__':
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
    while True:
        choice = input(prompt)

        if choice not in ['0','1','2']:
            print('Invalid input, try again')

        else:

            methodChoice = input(promptMethod)

            if methodChoice not in ['1','2']:
                print('Invalid method choice, try again')

            else:
                file_path = input(promptPath)
                key_path = input(promptKey)
                if choice == '1':
                    if methodChoice == '1':
                        encrypt_no_auth(file_path, key_path)
                    elif methodChoice == '2':
                        encrypt_auth(file_path, key_path)
                elif choice == '2':
                    if methodChoice == '1':
                        decrypt_no_auth(file_path, key_path)
                    elif methodChoice == '2':
                        decrypt_auth(file_path, key_path)
                elif choice == '0':
                    exit()
                else:
                    print('Invalid input, try again')