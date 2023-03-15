import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES

#Custom error
class SymmetricError(Exception):
  '''Error executing the script'''
class MenuError(SymmetricError):
  '''Invalid choice!'''
class WrongFiles(SymmetricError):
  '''Loaded files are not correct'''

# The encryption function without authentication, created following the ChaCha20 official guidelines.
# - "plaintext" is read from the user's computer.
# - the "key" is randomized.
# - "nonce" and "ciphertext" get encoded using b64
# - the result of the operation is then put inside of a json
# - the encrypted result and the key are saved where the user wants
def encrypt(plaintext):
  key = get_random_bytes(32)
  cipher = ChaCha20.new(key=key)
  ciphertext = cipher.encrypt(plaintext)
  nonce = b64encode(cipher.nonce)
  ct = b64encode(ciphertext)
  result = json.dumps({'nonce':nonce.decode('utf-8'), 'ciphertext':ct.decode('utf-8')})
  
  try:
    print("Where do you wanna save the file? (Select the folder)")
    write_file(getFolderPath(), result, 1)
    print("Where do you wanna save the key? (Select the folder)")
    write_file(getFolderPath(), str(key), -1)
    print("Operation successful.")
  except IOError as e:
    raise SymmetricError('Error: cannot write the message or the key: ' + str(e))

# The function that performs the decryption without authentication: the used method is ChaCha20 following the official guidelines.
# - json_input is a file that's been read from the user's computer containing "nonce" and "ciphertext".
# - key is also read from the user's computer.
# - once decoded with b64, cipher is initialized by passing the key and nonce, and it's used to decrypt the ciphertext.
# - the name of the function is the same of the cipher's built in one, but they are different functions.
# - the result of the decryption is saved where the user wants.
def decrypt(json_input, key):
  try:
    b64 = json.loads(json_input)
    nonce = b64decode(b64['nonce'])
    ciphertext = b64decode(b64['ciphertext'])
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
  except (ValueError, KeyError) as e:
    raise WrongFiles('Error: there seems to be a problem with the loaded files: ' + str(e))

  try:
    print("Where do you wanna save the file? (Select the folder)")
    write_file(getFolderPath(), plaintext.decode('utf-8'), 1)
    print("Operation successful.")
  except IOError as e:
    raise SymmetricError('Error: cannot save the decrypted file: ' + str(e))

# The encryption function with authentication, created following the AES official guidelines.
# - "data" is read from the user's computer.
# - the result of the operation is put inside of a json.
# - the encrypted result and the key are saved where the user wants.
def encryptAuth(data):
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_EAX)
  nonce = cipher.nonce
  ciphertext, tag = cipher.encrypt_and_digest(data)
  result = json.dumps({'nonce':str(nonce), 'ciphertext':str(ciphertext), 'tag':str(tag)})
  
  try:
    print("Where do you wanna save the file? (Select the folder)")
    write_file(getFolderPath(), result, 1)
    print("Where do you wanna save the key? (Select the folder)")
    write_file(getFolderPath(), key, -1)
    print("Operation successful.")
  except IOError as e:
    raise SymmetricError('Error: cannot write the message or the key: ' + str(e))


# The function that performs the decryption with authentication, created following the AES official guidelines.
# - "result" is a file that's been read from the user's computer containing "nonce", "ciphertext" and "tag".
# - "key" is also read from the user's computer.
# - I had some problems with the contents of the json this time so I had to do some per-index adjustments and decoding and re-encoding in a different format.
# - the problem was mainly due to the backslashes "\\" getting added with the bytes conversion.
# - the tag is verified after the decryption process.
# - the result of the decryption is saved where the user wants.
def decryptAuth(key, result):
  jsonContent = json.loads(result)
  nonce = bytes(jsonContent['nonce'][2:len(jsonContent['nonce'])-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
  ciphertext = bytes(jsonContent['ciphertext'][2:len(jsonContent['ciphertext'])-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
  tag = bytes(jsonContent['tag'][2:len(jsonContent['tag'])-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
  cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
  plaintext = cipher.decrypt(ciphertext)
  try:
    cipher.verify(tag)
  except ValueError:
    print("Something went wrong: the key may be incorrect or the message corrupted!")
  try:
    print("Where do you wanna save the file? (Select the folder)")
    write_file(getFolderPath(), plaintext.decode('utf-8'), 1)
    print("Operation successful.")
  except IOError as e:
    raise SymmetricError('Error: cannot save the decrypted file: ' + str(e))

# The function that reads a file from the computer.
# - path is the path of the file, passed when calling this function with getFilePath. The file's read as bytes.
def read_file(path):
  try:
    with open(path, 'rb') as in_file:
      out_str = in_file.read()
  except IOError as e:
    raise SymmetricError('Error: Cannot read ' + path + ' file: ' + str(e))
  return out_str

# The function that writes a file in a selected folder.
# - path is the path of the folder, passed when calling this function with getFolderPath. The file's written as bytes when it's the key.
def write_file(path, file, check):
  try:
    fileName = input("Choose the name of the file (make sure to save it as .txt): ")
    if(check==1):
      with open(path + '/' + fileName, 'w') as out_file:
        out_file.write(file)
    else:
      with open(path + '/' + fileName, 'w') as out_file:
        out_file.write(file)
  except IOError as e:
    raise SymmetricError('Error: cannot write the message or the key: ' + str(e))


# The function gets the path of the file by opening the explorer and selecting the file.
def getFilePath():
  root = tk.Tk()
  root.withdraw()
  root.call('wm', 'attributes', '.', '-topmost', True)
  return filedialog.askopenfilename()

# The function gets the path of the folder by opening the explorer and selecting the folder.
def getFolderPath():
  root = tk.Tk()
  root.withdraw()
  return filedialog.askdirectory()

# The main method with main menu and sub menus.
while True:
  prompt = '''What do you want to do?
  1 -> encrypt
  2 -> decrypt
  0 -> quit
 -> '''
  promptMethod = '''Which method do you prefer?
    1 -> No authentication (Choose file)
    2 -> Authentication (Choose file)
    0 -> Back
  -> '''

  choice = input(prompt)
  try:
    if choice == '1':
     
      choiceMethod = input(promptMethod)
      if choiceMethod == '1':
        ct = read_file(getFilePath())
        encrypt(ct)
      elif choiceMethod == '2':
        act = read_file(getFilePath())
        encryptAuth(act)
      elif(choiceMethod!='0'):
        print('Invalid choice, please try again!')
    elif choice == '2':
      choiceMethod = input(promptMethod)
      if choiceMethod == '1':
        ct = read_file(getFilePath())
        print('Select the decryption key (Choose file): ')
        key = read_file(getFilePath())
        decrypt(ct, key)
      elif choiceMethod == '2':
        act = read_file(getFilePath())
        print('Select the decryption key (Choose file): ')
        key = read_file(getFilePath())
        decryptAuth(key, act)
      elif(choiceMethod!='0'):
        print('Invalid choice, please try again!')
    elif choice == '0':
      exit()
    else:
      print('Invalid choice, please try again!')
  except MenuError as e:
    print(e)