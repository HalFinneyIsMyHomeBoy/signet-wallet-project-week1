#from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
#from subprocess import run
#from typing import List, Tuple

from hashlib import sha256
#import based58
#import hmac
import json

# Provided by administrator
WALLET_NAME = "wallet_000"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPfCxvMSGLjZegGFnZn9VZfVdsnEbuzTGdS9aZjvaYpyh7NsxsrAc8LsRQZ2EYaCfkvwNpas8cKUBbptDzadY7c3hUi8i33XJ"

#https://bitcoin.stackexchange.com/questions/114554/get-extended-public-key-from-extended-private-key-in-python

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
base_count = len(ALPHABET)

def convertBase58toint(s):
	""" Decodes the base58-encoded string s into an integer """
	decoded = 0
	multi = 1
	s = s[::-1]
	for char in s:
		decoded += multi * ALPHABET.index(char)
		multi = multi * base_count
		
	return decoded



priv = SigningKey.from_string(lastbytes, curve=SECP256k1)
print(priv)

#print(bigint)
#test = 'thing'
#result = str(sha256(bigint) )
#print(result.hexdigest()) 



#pub = priv.get_verifying_key().to_string()

#spub = pub.decode('utf-8')


#bytes_val = bigint.to_bytes(196, 'big') 

#print(bytes_val)

#print (decode_base58(EXTENDED_PRIVATE_KEY))

def get_pub_from_priv(priv: bytes) -> bytes:

    private_key_bytes = bytes.fromhex(priv['key_data'][2:])

    # Create a signing key using the private key
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Get the verifying key (public key)
    verifying_key = signing_key.get_verifying_key()

    # Compress the public key
    compressed_public_key = verifying_key.to_string('compressed')

    # Return the compressed public key as hex
    return compressed_public_key.hex()


bigint = convertBase58toint(EXTENDED_PRIVATE_KEY)
#print(bigint)
#lastbytes = str(bigint)[-32:].encode('utf-8')
#print(lastbytes)
tobytes = bigint.encode()
thing = get_pub_from_priv(tobytes)
print(thing)
 
# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)