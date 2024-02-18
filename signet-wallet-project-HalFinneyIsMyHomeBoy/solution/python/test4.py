from bip32utils import Base58

import hashlib
import binascii
import ecdsa
import random

def hash160(x): # Both accepts & returns bytes
    return hashlib.new('ripemd160', hashlib.sha256(x).digest()).digest()

def SegWit_address(pk, testnet=False):

    # The Script sig is PUSH(20) and then Hash160(pk) and where pk is the compressed public key
    push_20 = bytes.fromhex("0014")
    script_sig = push_20 + hash160(bytes.fromhex(pk))

    prefix = b"\xc4" if testnet else b"\x05"
    address = Base58.check_encode(prefix + hash160(script_sig))
    return address

def pubKeyToAddr(s):
    ripemd160 = hash160(bytes.fromhex(s))
    return '1'+Base58.check_encode(ripemd160)

def privateKeyToWif(key_hex):    
    return Base58.check_encode(bytes.fromhex(key_hex))
    
def privateKeyToPublicKey(s):
    pk = ecdsa.SigningKey.from_string(bytes.fromhex(s), curve=ecdsa.SECP256k1)
    pk=pk.get_verifying_key().to_string()
    pk="04"+binascii.b2a_hex(pk).decode()
    return (pk)
    
private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])

print ('Private key: ',private_key)
pub = privateKeyToPublicKey(private_key)
print ('\nPublic key: ',pub)
print ('\nWif: ',privateKeyToWif(private_key))
print ('\nAddress: ',pubKeyToAddr(private_key))

print ("\n===BIP 141===")

print ("SegWit address: ",SegWit_address(pub))
print ("Test net: ",SegWit_address(pub, testnet=True))
