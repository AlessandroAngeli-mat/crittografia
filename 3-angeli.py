"""
This module provides a host of functions that allow the user to:
- Generate key pairs
- Generate a private encrypted key
- Generate a public key given an encrypted private key
- Encrypt a file
- Decrypt a file


############# Original work prompt #############

Scrivere un programma in python (python3) chiamato '3-cognome.py'
(tutto minuscolo) che permetta di gestire uno scambio di file cifrati
tramite cifratura ibrida.
In particolare il programma deve gestire le seguenti operazioni:
1) Creazione di chiavi asimmetriche: creare una coppia di chiavi RSA
   (pubblica/privata) rispettando le corrette pratiche di sicurezza.
   Le chiavi andranno poi salvate su file con nome a scelta dell'utente,
   proteggendo bene la chiave privata.
2) Cifratura di file: cifrare un file seguendo uno schema di cifratura ibrida
   o di key encapsulation. L'utente deve poter cifrare un qualsiasi file,
   indicare un qualsiasi file contenente la chiave pubblica del destinatario,
   scegliere un qualsiasi nome per il file cifrato.
3) Decifratura di file: decifrare un file ricavando la chiave di sessione
   tramite una propria chiave privata. L'utente deve poter scegliere un
   qualsiasi file da decifrare, indicare un qualsiasi file contenente
   la propria chiave privata, scegliere un qualsiasi nome per il file
   dove salvare il file decifrato.


Il programma deve gestire correttamente tutte le eccezioni che possono
 essere lanciate dai vari metodi, seguire pratiche crittografiche
 corrette e le best practice viste in classe, essere il più chiaro
 possibile (commentate a dovere), evitare di avere codice duplicato.

############# End of prompt #############


This code has been rated 9.94/10 by pylint 2.16.1
(points deducted due to module name 3-angeli not conforming to snake_case)
"""


import sys
from getpass import getpass
from genericpath import isfile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''


class ReadProcessingError(HybEncError):
    '''Error preprocessing data read from file'''


class KeyHandlingError(HybEncError):
    '''Error handling a key'''


#
# KEY functions
#

# function that reads a key from a file
# - private is a boolean that tells the function whether the key
#   being acquired is private or not, which determines the settings
#   that are passed to the read_file function
# it returns the key and ignores the file_path returned by read_file

def get_key(private: bool):
    """
    Function that reads a key from a file
    - private is a boolean that tells the function whether the key
      being acquired is private or not, which determines the settings
      that are passed to the read_file function\n
    It returns the key and ignores the file_path returned by read_file"""


    settings = {
        'subject': 'public key',
        'error': 'Public key import error',
        'default': 'public.pem'
    }
    if private:

        key_length = get_key_length()

        settings = {
        'subject': 'private key',
        'error': 'Private key import error',
        'default': 'private.pem',
        'process': lambda data: check_c_len(data, key_length/8)
        }


    key, _ = read_file(**settings)

    return key



# function that writes a key to a file
# - private is a boolean that tells the function whether the key
#   being written is private or not, which determines the settings
#   that are passed to the write_file function
# - key is a parameter containing any kind of key
# returns nothing

def write_key(private: bool, key):
    """
    Function that writes a key to a file
    - private is a boolean that tells the function whether the key
      being written is private or not, which determines the settings
      that are passed to the write_file function
    - key is a parameter containing any kind of key\n
    Returns nothing"""

    settings = {
        'data': key,
        'subject': 'public key',
        'error': 'Error writing public key to file',
        'default': 'public.pem'
    }
    if private:
        settings = {
        'data': key,
        'subject': 'private key',
        'error': 'Error writing private key to file',
        'default': 'private.pem'
        }

    write_file(**settings)


# function that uses the RSA library to generate a private key
# the key is created with 2048 bits
# the key is then exported in PEM format, secured with a key generated
# using the scrypt KDF with a password given by the user
# the key is then written to a file chosen by the user
# Returns the key's length
# cannot raise any errors

def generate_private_key():
    """
    Function that uses the RSA library to generate a private key\n
    The key is created with 2048 bits\n
    The key is then exported in PEM format, secured with a key generated
    using the scrypt KDF with a password given by the user\n
    The key is then written to a file chosen by the user\n
    Cannot raise any errors
    Returns the key's length"""

    length = get_key_length()

    key = RSA.generate(length)

    key = key.export_key(format='PEM', passphrase=get_passphrase(),
    pkcs=8, protection='scryptAndAES192-CBC')

    write_key(True, key)


# function that takes an encrypted key as an argument and decrypts it
# it does so by asking the user for a password
# - key is a parameter that contains the encrypted key to be decrypted
# returns the decrypted key

def decrypt_key(key):
    """
    Function that takes an encrypted key as an argument and decrypts it,
    it does so by asking the user for a password
    - key is a parameter that contains the encrypted key to be decrypted\n
    Returns the decrypted key"""

    imported = False

    while not imported:

        try:

            imported = True

            key = RSA.import_key(key, passphrase = get_passphrase())


        except ValueError as value_error:
            imported = False
            print(f"""\nError while decrypting key: {value_error}
You might have inputted a wrong password\n""")
            # let user abort
            choice = input('q to quit, anything else to try again: ')
            if choice.lower() == 'q':
                # abort
                raise KeyHandlingError("\nQuit succesfully!") from value_error

        if imported:
            return key


# function that generates a public key from a private key
# it asks the user for the file containing the encrypted private key
# it then decrypts it and uses it to generate a public key
# the public key is written to a file of the user's choice

def generate_public_key():
    """
    Function that generates a public key from a private key\n
    It asks the user for the file containing the encrypted private key\n
    It then decrypts it and uses it to generate a public key\n
    The public key is written to a file of the user's choice\n
    Cannot raise any errors"""

    enc_key = get_key(True)

    key = decrypt_key(enc_key)

    pub = key.public_key().export_key('PEM')

    write_key(False, pub)


#
# ENCRYPTION/DECRYPTION functions
#


# function that encrypts a file using the public key
# the file containing the public key is given by the user
# a new PKCS1_OAEP cipher is created using the key
# the user is also asked for the file containing the plaintext
# this cipher is used to encrypt the plaintext
# the encrypted plaintext is then written to a file chosen by the user
#
# WARNING: due to PKCS1 limitations, only files of less than 190 bytes
# can be encrypted

def encrypt_file():
    """
    Function that encrypts a file using the public key\n
    The file containing the public key is given by the user\n
    The key is used to create a new PKCS1_OAEP cipher
    which is then used to encrypt the plaintext\n
    The user is also asked for the file containing the plaintext
    which gets encrypted and written to a file chosen by the user\n
    ###  WARNING: due to PKCS1 limitations, only files of less than 190 bytes
    ###  can be encrypted"""


    imported = False


    while not imported:

        try:

            enc_key = get_key(False)
            imported = True
            key = RSA.import_key(enc_key)

        except ValueError as value_error:
            imported = False
            print(f"""There was an error importing the key: {value_error}
Could you have used the private key?""")
            choice = input('q to quit, anything else to try again: ')
            if choice.lower() == 'q':
                # abort
                raise KeyHandlingError('\nQuit succesfully!') from value_error


    cipher = PKCS1_OAEP.new(key)

    plaintext, file_path = read_file('plaintext', 'Error reading plaintext file', '', lambda x:x)


    try:

        ciphertext = cipher.encrypt(plaintext)
        write_data(True, ciphertext)


    except ValueError as value_error:
        print(f"""\nError while encrypting {file_path}:\n\n{str(value_error)}
        \nCould your file be bigger than 190 bytes?\n""")
        #let user abort
        choice = input('q to quit, anything else to try again: ')
        if choice.lower() == 'q':
            #abort
            raise HybEncError('\nQuit succesfully!') from value_error


# function that decrypts files
# it asks the user for the file containing the private key
# it also asks for the password needed to decrypt the key
# it then uses the key to decrypt the content of the file given by the user
# lastly, it saves the decrypted content in a file of the user's choice

def decrypt_file():
    """
    Function that decrypts files\n
    It asks the user for the file containing the private key\n
    It also asks for the password needed to decrypt the key,
    it then uses the key to decrypt the content of the file given by the user\n
    The decrypted content is saved in a file of the user's choice"""


    enc_key = get_key(True)


    key = decrypt_key(enc_key)


    cipher = PKCS1_OAEP.new(key)


    file_path = ''

    decrypted = False

    while not decrypted:

        try:

            decrypted = True
            ciphertext, file_path = read_file('encrypted',
            'Error reading encrypted file', 'encrypted.enc')
            plaintext = cipher.decrypt(ciphertext)
            write_data(False, plaintext)

        except ValueError as value_error:
            decrypted = False
            print(f"""\nError while decrypting {file_path}:\n\n{str(value_error)}
            \nCould you have chosen the wrong file?\n""")
            #let user abort
            choice = input('q to quit, anything else to try again: ')
            if choice.lower() == 'q':
                #abort
                raise HybEncError('\nQuit succesfully!') from value_error


#
# INPUT/OUTPUT functions
#


# function that asks the user for a length
# and checks the validity of it
# returns the key length

def get_key_length():
    """
    Function that asks the user for a length
    and checks the validity of it\n
    Returns the key length"""

    valid = False

    valid_values = [1024, 2048, 3072]

    prompt = f"""\nPlease input how many bits the key should be long
It should be one of these three values: {valid_values}
-> """

    while not valid:

        length = input(prompt)

        try:

            length = int(length)

            if length in valid_values:

                valid = True

            else:

                print(f'\nWrong input, it should be one of these: {valid_values}')

        except ValueError:
            print('\nYou must write an integer number!')


    return length


# function that specifies the settings for write_data
# - encrypted is a boolean that tells the function whether the data
#   being given is encrypted or not, which determines the settings
#   that are passed to the write_file function
# - data is a parameter containing any kind of data
# returns nothing

def write_data(encrypted: bool, data):
    """
    Function that specifies the settings for write_data
    - encrypted is a boolean that tells the function whether the data
      being given is encrypted or not, which determines the settings
      that are passed to the write_file function
    - data is a parameter containing any kind of data\n
    Returns nothing"""

    settings = {
        'data': data,
        'subject': 'decrypted data',
        'error': 'Error writing decrypted data',
        'default': 'decrypted (unless it is text, add the correct extension)'
    }
    if encrypted:
        settings = {
        'data': data,
        'subject': 'encrypted data',
        'error': 'Error writing encrypted data',
        'default': 'encrypted.enc'
        }


    write_file(**settings)


# funtion that reads files
# parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#       reading is not considered complete unless
#       this function is called successfully.
#       Should raise ReadProcessingError on errors
# returns data read (and processed) and name of file read

def read_file(subject, error, default='', process=lambda data: data):
    """
    Function that reads files
    Parameters:
    - subject: what the file should contain
    - error: error message to show when aborting
    - default: name of file to open if not specified
    - process: function to call on data,
      reading is not considered complete unless
      this function is called successfully.\n
    Should raise ReadProcessingError on errors\n
    Returns data read (and processed) and name of file read"""
    #prepare string to print, including default choice
    prompt = 'Insert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')'
    prompt += ':\n'
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as errors:
            print('Error while reading '+subject+':\n'+str(errors))
            #let user abort reading file
            choice = input('q to quit, anything else to try again: ')
            if choice.lower() == 'q':
                #abort
                raise HybEncError(error) from errors


# function to write on file
# parameters:
# - data: what to write to file
# - subject: description of what the file will contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# returns name of file written

def write_file(data, subject, error, default=''):
    """
    Function to write on file\n
    Parameters:
    - data: what to write to file
    - subject: description of what the file will contain
    - error: error message to show when aborting
    - default: name of file to open if not specified\n
    Returns name of file written"""
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = 'Insert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')'
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as io_error:
            print('Error while saving '+subject+': '+str(io_error))
            # let user abort writing file
            choice = input('q to quit, anything else to try again: ')
            if choice.lower() == 'q':
                # abort
                raise HybEncError(error) from io_error


#
# VALIDATION FUNCTIONS
#


# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have

def check_c_len(data, c_len):
    """
    Function that validates ciphertext file length\n
    Parameters:
    - data: byte string to check
    - c_len: length in bytes the key must have\n
    Returns the data after checking its length"""
    if len(data) >= c_len:
        return data
    message = 'Error: the ciphertext must be at least '
    message += str(c_len) + ' bytes long.'
    raise ReadProcessingError(message)


# function that acquires a non-empty passphrase
# for private key protection

def get_passphrase():
    """
    Function that acquires a non-empty passphrase,
    for private key protection\n
    Returns the password"""
    prompt = "Insert password for the private key:"
    while True:
        password = getpass(prompt)
        if password != '':
            return password
        prompt = "Please enter a non-empty password:"


# main function that does not get called when importing the file
def ask_user():
    """
    Main function with the interactive terminal prompts and case switching"""

    prompt = """
    What would you like to do?
    1) Generate key pair
    2) Generate encrypted private key
    3) Generate public key from private key
    4) Encrypt a file
    5) Decrypt a file
    0) Quit
-> """


    while True:
        choice = input(prompt)
        try:
            match choice:
                case '1':
                    generate_private_key()
                    generate_public_key()
                case '2':
                    generate_private_key()
                case '3':
                    generate_public_key()
                case '4':
                    encrypt_file()
                case '5':
                    decrypt_file()
                case '0':
                    sys.exit('Succesfully quit the program as per user choice')
                case _:
                    print('Invalid input, please try again!')
        except HybEncError as hyb_enc_error:
            print(str(hyb_enc_error))

# main
if __name__ == '__main__':
    ask_user()
