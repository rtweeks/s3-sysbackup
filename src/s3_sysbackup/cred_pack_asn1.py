# s3-sysbackup - Efficient, Unix-philosophy backup to S3 for Linux
# Copyright (c) 2021 Richard T. Weeks
# 
# GNU GENERAL PUBLIC LICENSE
#    Version 3, 29 June 2007
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from asn1crypto.core import Any, Integer, ObjectIdentifier, OctetString, Sequence
from Crypto.Cipher import AES
from Crypto.Util import Padding
import hashlib
import os
import typing as t
from unicodedata import normalize as str_norm

class Envelope(Sequence):
    _fields = [
        ('keyDerivation', ObjectIdentifier),
        ('encryption', ObjectIdentifier),
        ('keyDerivationParams', Any),
        ('encryptionParams', Any),
        ('cipherData', OctetString), # PKCS #7 padded JSON
    ]
    
    @classmethod
    def new(cls, kd_params, cipher_params):
        result = cls()
        result['keyDerivation'] = kd_params.ID
        result['keyDerivationParams'] = kd_params
        result['encryption'] = cipher_params.ID
        result['encryptionParams'] = cipher_params
        return result
    
    def derive_key(self, password: bytes) -> bytes:
        key_deriv_alg = ALGORITHMS[self['keyDerivation'].native]
        cipher_alg = ALGORITHMS[self['encryption'].native]
        engine = self['keyDerivationParams'].parse(key_deriv_alg)
        return engine.derive(password, keylen=cipher_alg.KEY_LENGTH)
    
    def ciphertext(self, password: bytes) -> '_Encrypted':
        return _Encrypted(self, self.derive_key(password))

def password_bytes(password: str) -> bytes:
    return str_norm('NFKD', password).encode('utf-8')

class _Encrypted:
    def __init__(self, envelope: Envelope, key: bytes):
        super().__init__()
        self.envelope = envelope
        self.key = key
    
    @property
    def cipher_alg(self):
        return ALGORITHMS[self.envelope['encryption'].native]
    
    @property
    def cipher(self):
        return self.envelope['encryptionParams'].parse(self.cipher_alg)
    
    def set(self, message: bytes):
        encrypt = self.cipher.encrypter(self.key)
        self.envelope['cipherData'] = encrypt(message)
    
    def get(self, ) -> bytes:
        decrypt = self.cipher.decrypter(self.key)
        return decrypt(self.envelope['cipherData'].native)

ALGORITHMS = {}
def _algorithm(t):
    ALGORITHMS[t.ID] = t
    return t

@_algorithm
class ScryptParams(Sequence):
    ID = '1.3.6.1.4.1.11591.4.11'
    SALT_LENGTH = 16
    _fields = [
        ('salt', OctetString),
        ('costParameter', Integer),
        ('blockSize', Integer),
        ('parallelizationParameter', Integer),
        ('keyLength', Integer),
    ]
    
    def derive(self, input: bytes, *, keylen=None):
        if keylen is not None and keylen != self['keyLength'].native:
            raise ValueError(
                "Key length mismatch between derivation ({}) "
                "and encryption ({})".format(
                    self['keyLength'].native, keylen
                )
            )
        
        return hashlib.scrypt(
            input,
            salt=self['salt'].native,
            n=self['costParameter'].native,
            r=self['blockSize'].native,
            p=self['parallelizationParameter'].native,
            dklen=self['keyLength'].native,
            maxmem=1 << 30,
        )
    
    @classmethod
    def from_hashlib_params(cls, salt, n, r, p, dklen, maxmem=None):
        result = cls()
        result['salt'] = salt
        result['costParameter'] = n
        result['blockSize'] = r
        result['parallelizationParameter'] = p
        result['keyLength'] = dklen
        return result

@_algorithm
class AES_256_CBC_Params(Sequence):
    ID = '2.16.840.1.101.3.4.1.42'
    KEY_LENGTH=32
    _fields = [
        ('iv', OctetString),
    ]
    
    @classmethod
    def new(cls, ):
        result = cls()
        result['iv'] = os.urandom(16)
        return result
    
    def cipher(self, key: bytes):
        return AES.new(key, AES.MODE_CBC, iv=self['iv'].native)
    
    def encrypter(self, key: bytes):
        def encrypt(message: bytes):
            c = self.cipher(key)
            return c.encrypt(Padding.pad(message, c.block_size, style='pkcs7'))
        
        return encrypt
    
    def decrypter(self, key: bytes):
        def decrypt(message: bytes):
            c = self.cipher(key)
            return Padding.unpad(c.decrypt(message), c.block_size, style='pkcs7')
        
        return decrypt
