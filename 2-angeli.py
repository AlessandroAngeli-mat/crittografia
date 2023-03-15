# symmetric encryption (with only authenticated mode) using a password to derive the key

# import cryptography modules
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt #import the password-based key derivation function
from getpass import getpass #importing the getpass module used to take a password as an input

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''



# function that handles file input
# parameters:
# - prompt: message to display acquiring file path
# - validate: function that validates content read,
#   should raise a ValidationError on invalid inputs
# tries to read valid content until success or user aborts

def read_file(prompt, validate = lambda x : None):
  # repeat until a validated input is read or user aborts
  while True:
    # acquire file path
    path = input(prompt)
    # read input managing IOErrors
    try:
      # read content as bytes
      with open(path, 'rb') as in_file:
        content = in_file.read()
      try:
        # validate contents
        validate(content)
        # validation successful, return content (end of function)
        return content
      except ValidationError as err:
        # print validation error
        print(err)
    except IOError as err:
      print('Error: Cannot read file ' + path + ': ' + str(err))
    # no valid content read: try again or abort
    choice = input('(q to abort, anything else to try again) ')
    if choice == 'q':
      raise SymEncError('Input aborted')




# function that handles file output
# parameters:
# - prompt: message to display acquiring file path
# - data: bytes to be written in file
# tries to write data until success or user aborts

def write_file(prompt, data):
    # repeat until  write or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # write input managing IOErrors
        try:
            # write content as bytes
            with open(path, 'wb') as out_file:
                out_file.write(data)
            return 'Data ly written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file ' + path + ': ' + str(e))
        # write unsuccessful: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Output aborted')



# function that generates prompts for reading and writing files
# parameters:
# - f_type: string that describes the file
# - read: boolean that tells if the prompt is for input or not

def gen_prompt(f_type, reading):
    message = "Please insert path of the file "
    if reading:
        message += "that contains the " + f_type
    else:
        message += "where to save the " + f_type
    return message + ": "


# function that gets the password from the user
# it uses the getpass library to get the input without printing on screen
# returns a string containing the password
def get_password():
    prompt = "Type the password: "
    password = getpass(prompt=prompt)
    return password

# function that generates either a key or both the salt and the key
# - encrypting is a boolean that tells the function whether the user is encrypting or not
# - salt is a variable that either contains 0, which will be overwritten by 16 random bytes,
#   or the salt passed by the user
# returns either both the key and the salt (when encrypting), or just the key (when decrypting)
def generate_key_salt(encrypting:bool, salt: bytes = b''):
    # if the user is encrypting generate a random salt
    if encrypting:
        salt = get_random_bytes(16)
    # generate the key using the given password and the salt
    key = scrypt(get_password(), salt, 16, N=2**20, r=8, p=1)
    # if the user is encrypting return both the key and the salt, otherwise only the key is returned
    if encrypting:
        return key, salt
    else:
        return key

# function that performs encryption
# it takes the salt and the key generated by the function get_key_salt
# it also writes the salt in the output file

def encrypt():
  # read file to encrypt, no validation
  p_data = read_file(gen_prompt("data to encrypt", True))
  # encryption
  key, salt = generate_key_salt(True)
  cipher = AES.new(key, AES.MODE_OCB)
  ciphertext, tag = cipher.encrypt_and_digest(p_data)
  c_data = cipher.nonce + tag + salt + ciphertext
  # output
  print(write_file(gen_prompt("encrypted data", False), c_data))


# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have

def check_c_len(data, c_len):
    if len(data) < c_len:
        err_msg = 'Error: the ciphertext must be at least '
        err_msg += str(c_len) + ' bytes long, the input was '
        err_msg += str(len(data)) + ' bytes long.'
        raise ValidationError(err_msg)



# function that performs decryption
# it checks that the encrypted data is long enough
# it reads all the necessary info from the file given by the user
# it then calls the generate_key_salt function to generate the key 
# it tries to decrypt the encrypted content and to write it to a file

def decrypt():
  # read ciphertext validating its length
  c_data = read_file(
      gen_prompt("data to decrypt", True),
      lambda data: check_c_len(data, 47)
  )
  # decryption
  nonce = c_data[:15]
  tag = c_data[15:31]
  salt = c_data[31:47]
  ciphertext = c_data[47:]
  key = generate_key_salt(False, salt)
  cipher = AES.new(key, AES.MODE_OCB, nonce)
  try:
      p_data = cipher.decrypt_and_verify(ciphertext, tag)
  except ValueError:
      raise SymEncError('Decryption error: authentication failure')
  # output
  print(write_file(gen_prompt("decrypted data", False), p_data))


if __name__ == '__main__':
    # main
    main_prompt = '''What do you want to do?
    1 -> encrypt
    2 -> decrypt
    0 -> quit
    -> '''

    password_prompt = '''Please insert the password
    -> '''

    while True:
        # get user's choice and call appropriate function
        # errors are captured and printed out
        choice = input(main_prompt)
        try:
            match choice:
                case '1':
                    encrypt()
                case '2':
                    decrypt()
                case '0':
                    exit()
                case _:
                    # default error message for wrong inputs
                    print('Invalid choice, please try again!')
        except SymEncError as e:
            print(e)