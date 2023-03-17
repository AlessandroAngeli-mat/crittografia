
# importare i moduli crittografici
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import BLAKE2b
# importare una funzione di input
from getpass import getpass
import json
import os.path

def load_data(path, password):
    with open(path, 'rb') as in_file:
        # scomponi i dati letti in 4 pezzi, 3 hanno lunghezze precise
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
        
    # rendi i dati leggibili e salva il risultato in 'data'
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1) # ricava il segreto necessario per "sbloccare" i dati
    cipher = AES.new(key, AES.MODE_OCB, nonce) # setup della funzione che "sblocca" i dati
    data = cipher.decrypt_and_verify(ciphertext, tag) # sblocca i dati
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    # proteggi 'data' utilizzando opportunamente la password
    # ricava il segreto necessario per proteggere i dati
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    cipher = AES.new(key, AES.MODE_OCB)# setup della funzione che proteggere i dati
    ciphertext, tag = cipher.encrypt_and_digest(data) # proteggi i dati
    with open(path, 'wb') as out_file:
        # salva i dati protetti nel file situato in 'path'
        # (salvare anche i parametri necessari per sbloccarli)
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)


def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            # leggi la password in maniera opportuna
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic


def log_in(username, password):
    # deriva il percorso del file associato all'utente
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
    if username == '':
        print('Goodbye!')
        exit()
    else:
        # leggi la password in maniera opportuna
        password = getpass('Password: ')
        log_in(username, password)