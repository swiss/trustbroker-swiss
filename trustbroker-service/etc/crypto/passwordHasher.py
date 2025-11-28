import scrypt
import logging
import math
import base64
import os
import sys
from hashlib import pbkdf2_hmac, sha256
from argon2 import PasswordHasher


# Hash passwords for to protect them in storage
class PwHasher:
    salt = os.urandom(16)

    # scrypt.hash(password,salt,N,r,p,derivedKeyLength)
    # N – iterations count (affects memory and CPU usage), e.g. 16384 or 2048
    # r – block size (affects memory and CPU usage), e.g. 8
    # p – parallelism factor (threads to run in parallel - affects the memory, CPU usage), usually 1
    # password– the input password (8-10 chars minimal length is recommended)
    # salt – securely-generated random bytes (64 bits minimum, 128 bits recommended)
    # derivedKeyLength - how many bytes to generate as output, e.g. 32 bytes (256 bits)
    # Spring security format $params$saltBase64$hashBase64
    def to_scrypt(self, password):
        N = 2048
        r = 8
        p = 1
        derivedKeyLength = 32
        hashed = scrypt.hash(password, self.salt, N, r, p, derivedKeyLength)
        params = self.to_hexadecimal((int(math.log(N) / math.log(2)) << 16 | r << 8 | p))
        result = ("{scrypt}" + "$" + params + "$" + str(base64.b64encode(self.salt), 'utf-8') + "$"
                  + str(base64.b64encode(hashed), 'utf-8'))
        logging.debug(f"Hashing ClientSecret={password} to hash={result}")
        return result

    def to_hexadecimal(self, n):
        if n is None:
            return [0]
        # convert Decimal ot Hexadecimal with 5 digits
        return hex(n)[2:].rjust(5, '0')

    # pbkdf2(hash-function, password, salt, iterations-count, derived-key-len)
    # password – array of bytes / string, e.g. "p@$Sw0rD~3" (8-10 chars minimal length is recommended)
    # salt – securely-generated random bytes, e.g. "df1f2d3f4d77ac66e9c5a6c3d8f921b6" (minimum 64 bits, 128 bits is recommended)
    # iterations-count, e.g. 1024 iterations
    # hash-function for calculating HMAC, e.g. SHA256
    # derived-key-len for the output, e.g. 32 bytes (256 bits)
    def to_pbkdf2(self, password):
        hash = pbkdf2_hmac("sha256", password.encode('utf-8'), self.salt, 310000)
        result = "{pbkdf2@SpringSecurity_v5_8}" + (self.salt + hash).hex()
        logging.debug(f"Hashing ClientSecret={password} to hash={result}")
        return result

    # Spring security format is the same as the output $argon2id$v=19$m=65536,t=3,p=hash
    def to_argon2(self, password):
        ph = PasswordHasher()
        result = "{argon2}" + ph.hash(password)
        logging.debug(f"Hashing ClientSecret={password} to hash={result}")
        return result


def _main():
    if len(sys.argv) == 3:
        password = sys.argv[1]
        method = sys.argv[2]
        hasher = PwHasher()
        if "argon2" in method:
            print(hasher.to_argon2(password))
        if "scrypt" in method:
            print(hasher.to_scrypt(password))
        if "pbkdf2" in method:
            print(hasher.to_pbkdf2(password))
    else:
        print("Usage: passwordHasher.py PASSWORD_TO_HASH [argon2|scrypt|pbkdf2]")
        exit(1)


if __name__ == '__main__':
    _main()
