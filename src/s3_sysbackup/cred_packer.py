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

import boto3
import hashlib
import json
import math
import os
import time

from .cred_pack_asn1 import (
    Envelope,
    ScryptParams,
    AES_256_CBC_Params,
    password_bytes,
)
from .system_setup import ConsoleUserInterface

class CredPacker:
    def __init__(self, dest, *, ui=None):
        super().__init__()
        self.dest = dest
        self.ui = ConsoleUserInterface() if ui is None else ui
    
    def run(self, ):
        # Load credentials
        s = boto3.Session()
        creds = s.get_credentials()
        
        # Check credentials method and token
        if creds.method in ('shared-credentials-file', 'env'):
            if creds.token is not None:
                raise ValueError("Packing credentials with a session token is not supported")
        else:
            raise ValueError("Credentials method {!r} is not supported".format(
                creds.method
            ))
        
        kdwork_level = determine_scrypt_args()
        kdwork_params = ScryptParams.from_hashlib_params(
            salt=os.urandom(ScryptParams.SALT_LENGTH),
            dklen=AES_256_CBC_Params.KEY_LENGTH,
            **kdwork_level
        )
        
        # Query user for password
        password = self.ui.get_password(verify=True)
        
        # Encrypt credentials as JSON for boto3.Session kwargs in .cred_pack_asn1.Envelope
        pack = Envelope.new(kdwork_params, AES_256_CBC_Params.new())
        pack.ciphertext(password_bytes(password)).set(
            json.dumps(dict(
                aws_access_key_id=creds.access_key,
                aws_secret_access_key=creds.secret_key,
            )).encode('ascii')
        )
        
        self.dest.write(pack.dump())

STANDARD_SCRYPT_PARAMS = dict(r=8, p=16)

def determine_scrypt_args(seconds_on_this_machine=3):
    trial_n_pow = 10
    start = time.time()
    r_mem = math.ceil(math.log2(STANDARD_SCRYPT_PARAMS['r']))
    hashlib.scrypt(
        b'not a secret',
        n=1 << trial_n_pow,
        salt=b'ABCDEFGHIJKLMNOP',
        **STANDARD_SCRYPT_PARAMS,
        maxmem=1 << (10 + r_mem + 8),
    )
    end = time.time()
    factor = seconds_on_this_machine / (end - start)
    target_n_pow = trial_n_pow + round(math.log2(factor))
    n_pow = min(target_n_pow, 30 - r_mem - 8)
    p = STANDARD_SCRYPT_PARAMS['p'] << (target_n_pow - n_pow)
    maxmem = 1 << (n_pow + r_mem + 8)
    return dict(
        STANDARD_SCRYPT_PARAMS,
        n=1 << n_pow,
        p=p,
        maxmem=maxmem,
    )
