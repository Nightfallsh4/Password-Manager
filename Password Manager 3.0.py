#!/usr/bin/env python
# coding: utf-8

# In[1]:


import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secrets import choice
from Crypto.PublicKey import RSA


# In[2]:


l = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']

u = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

n = ['1','2','3','4','5','6','7','8','9','0']

s = ['!','@','#','$','%','^','&','*','_','+','|','?','-','=','`','~']


# In[3]:


def gen_password(length=16):
    """Generates a random password and returns it in Byte format"""
    pw = ''
    for i in range(length):
        li=choice([1,2,3,4])
        if li == 1:
            pw = pw+choice(l)
        elif li == 2:
            pw = pw+choice(u)
        elif li == 3:
            pw= pw+choice(n)
        elif li == 4:
            pw = pw+choice(s)
    pw = pw.encode()
    return pw


# In[4]:


def gen_private_key():
    try:
        """tries to read the encrypted private key file; if not able to find a private key file it generates one 
        and encrypts it with the symmetric key"""
        f=open("private_keys.txt","r")
        file = f.read()
        f.close()
    except:
        key = RSA.generate(4096)
        private_key = key.exportKey("PEM")
        private_key=sym_key.encrypt(private_key)
        f=open("private_keys.txt","w")
        f.write(private_key.decode())
        f.close()


# In[5]:


def key_gen():
    """Takes the master passwrod as the input and returns the Fernet class of the key"""
    master_pw = str(input("Enter your master password- "))
    master_pw=master_pw.encode()
    mysalt = b'V\xd4\xc2\xe8\xd5_\xae\x92\xdf\xf8\xc1#\xda\xa4\xb5L'
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256,length=32,salt=mysalt,iterations=1000000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(master_pw)).decode()
    return Fernet(key.encode())


# In[6]:


def decrypt_private_key():
    """Reads the encrypted private key file; decrypts and serializes it and returns the serialized private key"""
    f=open("private_keys.txt","r")
    file = f.read()
    f.close()
    private_key = serialization.load_pem_private_key(sym_key.decrypt(file.encode()), 
                                                     password=None, 
                                                     backend=default_backend())
    return private_key


# In[7]:


def encrypt_password(password):
    """Takes in the randomly generated password and uses the public key to encrypt it.
    Returns the encrypted password as Bytes"""
    public_key = private_key.public_key()
    cipher_mess = public_key.encrypt(password,
                                     padding.OAEP(
                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm = hashes.SHA256(),
                                    label=None))
    return cipher_mess


# In[8]:


def decrypt_password(cipher_mess):
    """Uses the passed encrypted chipher text in as string"""
    plain_text = private_key.decrypt(cipher_mess,
                                     padding.OAEP(
                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm = hashes.SHA256(),
                                    label=None))
    return plain_text


# In[9]:


def write_file(filename):
    """Enter the filename it wants to write as a positional argument"""
    p = open(f"{filename}.txt","wb")
    p.write(cipher_password)
    p.close()


# In[10]:


def read_file(filename):
    """Enter the filename it wants to read as an argument and returns it"""
    p = open(f"{filename}.txt","rb")
    file = p.read()
    p.close()
    return file


# In[12]:


while True:
    mode = str(input("Do you want to generate a password(g) or read an already existing one(r)? "))
    if mode.lower() == 'g':
        filename = str(input("Name of the site you creating the password for- "))
        while True:
            password = gen_password()
            print(f"This is the password- {password.decode()}")
            confirm = str(input("Are you okay with the password? (Y/N)-"))
            if 'y' in confirm.lower():
                break
        
        while True:
            try:
                sym_key=key_gen()
                gen_private_key()
                private_key=decrypt_private_key()
            except:
                print("The password you have given is the wrong password or the private key file is corrupted/wrong")
            else:
                break
        cipher_password=encrypt_password(password=password)
        write_file(filename=filename)
        exit = str(input("Do you want to exist? "))
        if 'y' in exit.lower():
            break
    elif mode.lower()=='r':
        while True:
            try:
                sym_key=key_gen()
                gen_private_key()
                private_key=decrypt_private_key()
            except:
                print("The password you have given is the wrong password or the private key file is corrupted/wrong")
            else:
                break
        while True:
            try:
                filename=str(input("Name of the site you want the see the password of- "))
                file = read_file(filename=filename)
                print(decrypt_password(file).decode())
            except:
                print("There was an error pls check the site name")
            else:
                break
        exit = str(input("Do you want to exist? "))
        
        if 'y' in exit.lower():
            break


# In[ ]:




