from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path

class CryptoError(Exception):
  '''An error has occured during the encryption/decryption process'''
class MenuError(Exception):
  '''An error has occured during the selection'''
class PathError(Exception):
    '''The path provided does not correspond to a file'''

# function that reads a key from a file and converts it from string to bytes
# - path must be string, it is the path of the file containing the key
# returns a byte type variable containing the key
def read_key(path: str):
  with open(path, "r") as key_file:
    key = key_file.read()
    key = bytes(key[2:len(key)-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
  return key

# function that takes makes sure the plaintext's length is a multiple of the block size by padding if needed
# - plaintext is a bytes variable that containes the plaintext
# - block_size is an integer that contains the block size
# returns a bytes plaintext with the padding adjusted
def adjust_plaintext_padding(plaintext: bytes, block_size: int):
  padding_length = block_size - (len(plaintext) % block_size)
  plaintext += bytes([padding_length]) * padding_length
  return plaintext

# function that removes the extra padding in the plaintext
# - plaintext is a bytes type variable that contains the plaintext
# returns a bytes plaintext with the padding removed
def remove_plaintext_padding(plaintext: bytes):
  padding_length = plaintext[-1]
  plaintext = plaintext[:-padding_length]
  return plaintext

# function that uses the pathlib library to check if a path corresponds to an existing file
# - path is a string containing the file path
# returns nothing, raises a custom PathError if the file does not exist
def check_if_file(path: str):
    path = Path(f'./{path}')
    return path.is_file()

# function that writes a string to a file
# - path is a string that contains the path of the file to write to
# - content is a variable that contains the content to be converted to string and written in the file
def write_file(path: str, content):
  with open(path, 'w') as file:
    file.write(str(content))

# function that asks the user for a file name, checks if it exists in the same directory of the script
# if it doesn't, it asks again until the user provides a file name that exists
# - prompt is a string that is printed on the screen for the user
# returns the file path given by the user
def get_right_file(prompt):
  non_esiste = True
  while non_esiste:
    file_path = input(prompt)

    if not check_if_file(file_path):
      print(f'The file called {file_path} does not exist, try again')
    else:
      non_esiste = False
  
  return file_path

# function that encrypts without authentication
# - file_path is given by the user
# - key_path is also given by the user
# it writes the key to the file asked to the user
# it writes both the initialization vector and the ciphertext to the file asked to the user
def encrypt_no_auth(file_path, key_path):
  # generate a unique nonce and key, both 16 bytes long
  block_size = 16
  iv = get_random_bytes(block_size)
  key = get_random_bytes(block_size)
  
  # read from file
  with open(file_path, "rb") as in_file:
    plaintext = in_file.read()
 
  # add padding if needed
  plaintext = adjust_plaintext_padding(plaintext, block_size)
  
  # generate a new AES cipher with the given key and initialization vector
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # encrypt the plaintext
  ciphertext = cipher.encrypt(plaintext)

  # write the key to the file
  write_file(key_path, key)
  
  # write the iv and the ciphertext to the file
  with open(file_path, "wb") as out_file:
    out_file.write(iv)
    out_file.write(ciphertext)

  print('Succesfully encrypted the message!')


# function that decrypts without authentication
# - file_path is given by the user
# - key_path is also given by the user
# it prints the original message on screen
# it writes the original text in the file containing the plaintext
def decrypt_no_auth(file_path, key_path):

  key = read_key(key_path)

  with open(file_path, "rb") as in_file:
    # read the initialization vector, which was set at 16 bytes, then read the rest, which is the ciphertext
    iv = in_file.read(16)
    ciphertext = in_file.read()     
  # generate a new AES cipher with the given key and initialization vector
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  # decrypt the ciphertext
  plaintext = cipher.decrypt(ciphertext)
  
  # remove the padding from the original
  plaintext = remove_plaintext_padding(plaintext)

  # convert the plaintext from bytes to string
  plaintext = plaintext.decode('utf-8')


  write_file(file_path, plaintext)

  print(f'Succcesfully decrypted the message, the original was: \n{plaintext}')


# function that encrypts using EAX, which uses authentication
# - file_path is the path of the file containing the tex to be encrypted
# - key_path is the path of the file where the generated key will be writte in cleartext
# the function writes the key to a file and the encrypted text to a different file, along with all the necessary information to decrypt
def encrypt_auth(file_path, key_path):
  # generate a unique nonce for each file
  block_size = 16
  nonce = get_random_bytes(block_size)
  key = get_random_bytes(block_size)

  with open(file_path, "rb") as in_file:
    # read the entire file
    plaintext = in_file.read()
  
  # add padding if needed
  plaintext = adjust_plaintext_padding(plaintext, block_size)
  
  # create a new AES cipher with the given key and nonce
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  
  # encrypt the plaintext
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)
  
  write_file(key_path, key)

  # open the output file in binary mode
  with open(file_path, "wb") as out_file:
    
    out_file.write(nonce)
    
    out_file.write(tag)
    
    out_file.write(ciphertext)

    
  print('Succesfully encrypted the message with authentication!')


# function that decrypts with authentication using EAX
# - file_path is the path of the file containing the tex to be decrypted
# - key_path is the path of the file where the key is stored, which will be read and used to decrypt
# the function prints the decrypted text on screen and writes it in the file which contained the encrypted text
def decrypt_auth(file_path, key_path):

  # get the key
  key = read_key(key_path)
  
  # open the input file in binary mode
  with open(file_path, "rb") as in_file:
    
    nonce = in_file.read(16)
    
    tag = in_file.read(16)
    
    ciphertext = in_file.read()
      
  # create a new AES cipher with the given key and nonce
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  
  # decrypt the ciphertext
  try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
  except ValueError as e:
    raise CryptoError(f'You have most likely tried to decrypt with authentication a file/key combination which was encrypted without it: {str(e)}')
  
  # remove the padding from the plaintext
  plaintext = remove_plaintext_padding(plaintext)
  
  # convert the plaintext from bytes to string
  plaintext = plaintext.decode('utf-8')
  
  write_file(file_path, plaintext)
    
  print(f'Succcesfully decrypted the message with authentication, the original was: \n{plaintext}')


# this only executes if the script is being launched directly, thus avoiding it running should the script be imported in other files
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
    promptPath = '''Specify the text file name (make sure you add .txt)
-> '''
    promptKey = '''Specify the key's file name (make sure you add .txt)
->'''
    invalidPrompt = "Invalid choice, try again"
    # ask the user for the necessary inputs while checking that they are not invalid, in which case the prompt is printed again
    while True:
      # ask the user what they want to do
        choice = input(prompt)

        # check if the input given by the user is allowed
        if choice not in ['0','1','2']:
            print(invalidPrompt)
        
        # if the input is 0 then the program ends
        if choice == '0':
            exit()

        else:
            # ask the user which method they want to use
            methodChoice = input(promptMethod)

            # check if the input is allowed
            if methodChoice not in ['1','2']:
                print(invalidPrompt)

            else:
                #get the right file path
                file_path = get_right_file(promptPath)

                match choice:

                    case '1':
                        # get the key path, creating a new file should the given path not match any file
                        key_path = input(promptKey)

                        match methodChoice:

                            case '1':
                                encrypt_no_auth(file_path, key_path)
                            case '2':
                                encrypt_auth(file_path, key_path)
                    case '2':
                        # get the right key path
                        key_path = get_right_file(promptKey)

                        match methodChoice:

                            case '1':
                                decrypt_no_auth(file_path, key_path)
                            case '2':
                                decrypt_auth(file_path, key_path)