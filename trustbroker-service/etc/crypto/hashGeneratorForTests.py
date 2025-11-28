#!/usr/bin/env python3

import logging
from passwordHasher import PwHasher

# Generates hashes to test interoperability with Spring
def _main():
	_setup_logging()
	pwHasher = PwHasher()

	logging.info(f"Hashing ClientSecret with Scrypt secret=" + pwHasher.to_scrypt("secret"))
	logging.info(f"Hashing ClientSecret with Scrypt test01=" + pwHasher.to_scrypt("test01"))

	logging.info(f"Hashing ClientSecret with PBKDF2SpringV5 secret=" + pwHasher.to_pbkdf2("secret"))
	logging.info(f"Hashing ClientSecret with PBKDF2SpringV5 test01=" + pwHasher.to_pbkdf2("test01"))

	logging.info(f"Hashing ClientSecret with Argon2 secret=" + pwHasher.to_argon2("secret"))
	logging.info(f"Hashing ClientSecret with Argon2 test01=" + pwHasher.to_argon2("test01"))

def _setup_logging():
	logging.basicConfig(format='%(asctime)s|%(levelname)s: %(message)s', level=logging.INFO)
	# logging.getLogger("requests").setLevel(logging.WARNING)
	logging.getLogger("urllib3").setLevel(logging.WARNING)

if __name__ == '__main__':
	_main()
