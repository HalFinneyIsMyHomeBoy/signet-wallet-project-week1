import hashlib 
from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
#from ripemd.ripemd160 import ripemd160
from subprocess import run
from typing import List, Tuple
#import based58
import hmac
import json
import binascii

# Provided by administrator
WALLET_NAME = "wallet_203"
#EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPfCxvMSGLjZegGFnZn9VZfVdsnEbuzTGdS9aZjvaYpyh7NsxsrAc8LsRQZ2EYaCfkvwNpas8cKUBbptDzadY7c3hUi8i33XJ"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPe3mqy45AhM54p45TSsx1so773AwymR5t3aKS2nJXtF4FZHC9N1jShs7t88GEKAfxSBZAezzH4Y2R9XyuKjbT5z8AKL4L2Fu"

#wpkh(tprv8ZgxMBicQKsPe3mqy45AhM54p45TSsx1so773AwymR5t3aKS2nJXtF4FZHC9N1jShs7t88GEKAfxSBZAezzH4Y2R9XyuKjbT5z8AKL4L2Fu/84h/1h/0h/0/*)#yls2rute
def base58_decode(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in base58_string:
        num = num * 58 + base58_alphabet.index(char)

    result = b""
    while num > 0:
        num, remainder = divmod(num, 256)
        result = bytes([remainder]) + result

    return result



# Deserialize the extended key bytes
def deserialize_key(b: bytes) -> dict:
    version = int.from_bytes(b[:4], byteorder='big')
    depth = b[4]
    fingerprint = int.from_bytes(b[5:9], byteorder='big')
    index = int.from_bytes(b[9:13], byteorder='big')
    chaincode = b[13:45]
    key_data = b[45:]

    return {
        "version": version,
        "depth": depth,
        "fingerprint": fingerprint,
        "index": index,
        "chaincode": chaincode,
        "key_data": key_data
    }


# Derive the key and chaincode at the specified path
def derive_key_at_path(xprv: str, path: List[Tuple[int, bool]]) -> Tuple[bytes, bytes]:
    decoded_xprv = base58_decode(xprv)
    deserialized_key_data = deserialize_key(decoded_xprv)

    key_data = deserialized_key_data["key_data"]
    chaincode = deserialized_key_data["chaincode"]

    derived_key_data = key_data
    derived_chaincode = chaincode
    print(derived_chaincode.hex())
    print(derived_key_data.hex())
    for index, hardened in path:
        derived = derive_priv_child(derived_key_data, derived_chaincode, index, hardened)
        derived_key_data = derived["key"]
        derived_chaincode = derived["chaincode"]

    return derived_key_data, derived_chaincode

# Perform a BIP32 parent private key -> child private key operation
# def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> dict:

#     if hardened: 
#         index += 0x80000000
#         data = b'\x00' + key + index.to_bytes(4, byteorder='big')
#     else:
#         data = key + index.to_bytes(4, byteorder='big')

#     hmac_result = hmac.new(chaincode, data, hashlib.sha512).digest()
#     left_part = int.from_bytes(hmac_result[:32], 'big')
#     right_part = hmac_result[32:]
    
#     new_key = (int.from_bytes(key, 'big') + left_part) % SECP256k1.order
#     new_key_bytes = new_key.to_bytes(32, 'big').rjust(32, b'\x00')

#     new_chaincode = right_part
    
#     return {"key": new_key_bytes, "chaincode": new_chaincode}

def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> object:
    curve = SECP256k1
    n = curve.order
    if hardened:
        index+=2**31
        data = b'\x00' + key + index.to_bytes(4, 'big')
    else:
        # data = (SigningKey.from_string(key, curve=SECP256k1).get_verifying_key().to_string("compressed")) + index.to_bytes(4, 'big')
        data = get_pub_from_priv(key) + index.to_bytes(4, 'big')
    
    hmac_res = hmac.new(chaincode, data, hashlib.sha512).digest()
    i1, chaincode_i = hmac_res[:32], hmac_res[32:]
    i = int.from_bytes(i1, 'big')
    child_key = (i + int.from_bytes(key, 'big'))%n
    return { "key": child_key.to_bytes(32, 'big'), "chaincode": chaincode_i }

# Derive 2000 private keys from the path
def get_wallet_privs(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    privs = [key]
    for index, hardened in path:
        derived = derive_priv_child(privs[-1], chaincode, index, hardened)
        privs.append(derived["key"])

    return privs

# Compute the compressed public key for each private key
def get_pub_from_priv(priv: bytes) -> bytes:
    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    vk = signing_key.get_verifying_key()
    version = 4
    #result = version.to_bytes(2, 'big') + binascii.b2a_hex(vk).decode()
    result = version.to_bytes(2, 'big') + vk.to_string("compressed")
    return result


# Compute the P2WPKH witness program for each compressed public key
def get_p2wpkh_program(pubkey: bytes, version: int = 0) -> bytes:
    
    shahash = hashlib.sha256(pubkey).digest()
    #print(shahash.hex())
    r = hashlib.new('ripemd160')
    r.update(shahash).hex()
    r.digest()
    #r = hashlib.ripemd160(bytes.fromhex(shahash)).hex()
    #print(r.hex())
    return bytes([version]) + r






def bcli(cmd: str):
    res = run(["bitcoin-cli", "-signet"] + cmd.split(" "), capture_output=True, encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())

# Look for you compressed public keys in all TX witnesses - these are coins you spent
# def blockscan(programs:bytes):
#     print(len(programs))    
#     for h in range(311):
#         hash=bcli(f"getblockhash {h}")
#         txs = json.loads(bcli(f"getblock {hash} 2"))["tx"]
#         i=0
#         for tx in txs:
#             #if (len(txs) > 1):
#                 #print('thing')
#             for i, prog in enumerate(programs):
#                 test = prog.hex()
#                 testhex = prog.hex()[2:] #the "2:" is there to remove the first two digits (version number)
#                 if prog.hex()[2:] in [out["scriptPubKey"]["hex"] for out in tx["vout"]]:                    
 
#                     print("match!!!!")

def recover_wallet_state(xprv: str):
    # Generate all the keypairs and witness programs to search for
    #privs = privs
    #pubs = pubs
    #programs = programs

    # Prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": 0,
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }

    # Scan blocks 0-310
    height = 310
    for h in range(height + 1):
        hash=bcli(f"getblockhash {h}")
        txs = json.loads(bcli(f"getblock {hash} 2"))["tx"]
        # Scan every tx in every block
        print(str(h))

        for tx in txs:
            #mappedtx = json.loads(tx)
            a = pubs[0].hex()[4:]
            b = privs[0].hex()[4:]

            c=pubs[1].hex()[4:]
            d = privs[1].hex()[4:]
            # if(tx['vin'][0]['coinbase']):
            #     print('skipping coinbase ' + tx['vin'][0]['coinbase'])
            # else:
                # Check every tx input (witness) for our own compressed public keys.


            #for vins in tx['vin']:               
                #if('txinwitness' in vins):
                    #print(prog.hex()[2:])
                    #if(prog.hex()[2:] in vins['txinwitness']):
                       # print('txinwitness exists in block ' + str(h))
                        #print(prog.hex())    

            #for i, pub in enumerate(pubs):
                #print('thing')
                # These are coins we have spent.

            for vins in tx['vin']:               
                if('txinwitness' in vins):
                    if(len(vins['txinwitness']) > 1):
                        #print('transactions: ' + str(len(tx['vin'])))
                        for i, prog in enumerate(programs):
                        #print(str(i))
                            if(prog.hex()[2:] in vins['txinwitness'][1]):
                            
                                print('txinwitness exists in block ' + str(h))
                                print(prog.hex())
                
                #if '3f5c5ec43eae826f57cbb3f83d' in tx["vout"]["scriptPubKey"]["hex"].hex():
                    #print('thing')
                #for inp in tx["vin"]:
                    #if '6a013f5c5ec43eae826f57cbb3f83d' in [out["scriptPubKey"]["hex"] for out in tx["vout"]]:  
                        #print(inp | jq)
                    # Remove this coin from our wallet state utxo pool
                    # so we don't double spend it later

            # Check every tx output for our own witness programs.
            # These are coins we have received.
            #for out in tx["vout"]:
                #print(tx["vout"])
                #if prog.hex()[2:] in [out["scriptPubKey"]["hex"] for out in tx["vout"]]:  
                    #print('match')
                    # Add to our total balance

                    # Keep track of this UTXO by its outpoint in case we spend it later


path = [(0x84, False), (0x01, False), (0x00, False), (0x00, False)]  # 84h/1h/0h/0
derived_key, derived_chaincode = derive_key_at_path(EXTENDED_PRIVATE_KEY, path)
print(f"Derived Key: {derived_key.hex()}")
print(f"Derived Chaincode: {derived_chaincode.hex()}")


# Derive 2000 private keys from the path
path_2000 = [(i, True) for i in range(1999)]
privs = get_wallet_privs(derived_key, derived_chaincode, path_2000)
print('done')

# Compute the compressed public key for each private key
pubs = [get_pub_from_priv(priv) for priv in privs]
print('done')

programs = [get_p2wpkh_program(pub) for pub in pubs]
print('done')

#blockscan(programs)
recover_wallet_state(EXTENDED_PRIVATE_KEY)
