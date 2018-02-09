# -*- coding: utf-8 -*-
import base64
import json
import os
import tempfile
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from globaleaks.rest import errors
from globaleaks.utils.security import crypto_backend, generateRandomKey


class SecureTemporaryFileWrite(object):
    file = None
    mode = 'a+'

    def __init__(self, filesdir, keysdir):
        """
        Create the AES Key to encrypt the uploaded file and initialize the cipher
        """
        self.key = os.urandom(32)

        self.key_id = generateRandomKey(16)
        self.keypath = os.path.join(keysdir, "%s%s" %
                                    (keysdir, self.key_id))

        self.key_counter_nonce = os.urandom(16)

        key_json = {
            'key': base64.b64encode(self.key),
            'key_counter_nonce': base64.b64encode(self.key_counter_nonce)
        }

        with open(self.keypath, 'w') as kf:
            json.dump(key_json, kf)

        self.cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.key_counter_nonce), backend=crypto_backend)
        self.encryptor = self.cipher.encryptor()

        self.filepath = os.path.join(filesdir, "%s.aes" % self.key_id)

        self.open()

    def open(self):
        if self.file is None:
           self.file = open(self.filepath, self.mode)

    def write(self, data):
        self.open()

        if isinstance(data, unicode):
            data = data.encode('utf-8')

        self.file.write(self.encryptor.update(data))

    def finalize(self):
        self.open()
        self.file.write(self.encryptor.finalize())

    def close(self):
        self.file.close()
        self.file = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()



class SecureTemporaryFileRead(SecureTemporaryFileWrite):
    mode = 'r'

    def __init__(self, filepath, keysdir):
        """
        Load the AES Key to decrypt the uploaded file and initialize the cipher
        """
        self.filepath = filepath

        self.key_id = os.path.basename(self.filepath).split('.')[0]

        self.keypath = os.path.join(keysdir, ("%s%s" % (keysdir, self.key_id)))

        with open(self.keypath, 'r') as kf:
            key_json = json.load(kf)

        self.key = base64.b64decode(key_json['key'])
        self.key_counter_nonce = base64.b64decode(key_json['key_counter_nonce'])

        self.cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.key_counter_nonce), backend=crypto_backend)
        self.decryptor = self.cipher.decryptor()

        self.open()

    def read(self, c=None):
        """
        The first time 'read' is called after a write, seek(0) is performed
        """
        self.open()

        if c is None:
            data = self.file.read()
        else:
            data = self.file.read(c)

        if data:
            return self.decryptor.update(data)

        return self.decryptor.finalize()
