from Crypto.Protocol.KDF import scrypt
# 
from Crypto.Cipher import AES
# imported to generate 16 random bytes used in the salt
# which is used in the key derivation process
from Crypto.Random import get_random_bytes
# blake2b was chosen because it is extremely fast, it is used in Argon2,
# the winner of the Password Hashing Competition, and it also protects
# against side channel attacks. 2b was chosen because it allows up to
# 64 bytes
from Crypto.Hash import BLAKE2b
# getpass is used because it allows the user to type the password
# without it being printed on the terminal
from getpass import getpass
import json
import os.path

# function that opens the file and decrypts it
# - path: string containing the path in which the file is located
# - password: string containing the password to use to derive the key
# returns the credentials contained in the file

def load_data(path, password):
    with open(path, 'rb') as in_file:
        # from the file, read the salt, the nonce, the tag and the ciphertext
        # in the order they were saved in
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
        
    # derive the key using the given password and the salt found in the file
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    # generate cipher
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    # decrypt ciphertext
    data = cipher.decrypt_and_verify(ciphertext, tag)
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

# function that encrypts and saves the file
# - path: string containing the path in which to save the file
# - password: string containing the password to use to derive the key
# - credentials: dict containing the credentials to save

def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    salt = get_random_bytes(16)
    # derive key from password and salt
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    # generate cipher
    cipher = AES.new(key, AES.MODE_OCB)
    # encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(path, 'wb') as out_file:
        # save protected data in the file found in 'path'
        # the parameters needed to unlock it are also saved
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

# function that looks for credentials and adds them if they don't exist
# - query: string containing the searched credentials
# - dic: dict extracted from the decypted file containing all credentials
# returns dic, whether it has been updated or not

def search_and_add(query, dic):
    # if credentials are found print them on screen
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    # if the credentials are not found, ask them to the user
    # and add them to the dict
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

# function that logs the user in
# - username: string containing the username to be hashed
# - password: string containing the password to be passed to load_data

def log_in(username, password):
    # hash the username and look for a file with that name
    blake_hash = BLAKE2b.new(data = username.encode('utf-8'), digest_bytes=64)
    path_file = blake_hash.hexdigest()
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    # if no file is found, ask to craete a new one
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    # ask the user the credentials to look for, save the file on empty input
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

#MAIN
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    # if no username is provided, quit
    if username == '':
        print('Goodbye!')
        exit()
    else:
        # read the password
        password = getpass('Password: ')
        log_in(username, password)