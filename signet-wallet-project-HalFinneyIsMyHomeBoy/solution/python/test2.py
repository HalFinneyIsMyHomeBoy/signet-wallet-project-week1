from __future__ import print_function
import cryptos

# Generate a random private key
valid_private_key = False
test="76152177352846528496452742875173"
while not valid_private_key:
    private_key = cryptos.random_key()
    decoded_private_key = cryptos.decode_privkey(test, 'hex')
    valid_private_key = 0 < decoded_private_key < cryptos.N
#test='04358394000000000000000000ea6f63babb3dc5c58ea4cd11cb3fc9d7baa51c0e14be8230ffb8b1696796a63f003cce48c84f22343cbdac8e7f252ed8ca11fce329deae7ed635b73822dfed9c779c430825'

print("Private Key (hex) is: ", private_key)
print("Private Key (decimal) is: ", decoded_private_key)

# Convert private key to WIF format
wif_encoded_private_key = cryptos.encode_privkey(decoded_private_key, 'wif')
print("Private Key (WIF) is: ", wif_encoded_private_key)

# Add suffix "01" to indicate a compressed private key
compressed_private_key = private_key + '01'
print("Private Key Compressed (hex) is: ", compressed_private_key)

# Generate a WIF format from the compressed private key (WIF-compressed)
wif_compressed_private_key = cryptos.encode_privkey(
    cryptos.decode_privkey(compressed_private_key, 'hex_compressed'), 'wif_compressed')
print("Private Key (WIF-Compressed) is: ", wif_compressed_private_key)

# Multiply the EC generator point G with the private key to get a public key point
public_key = cryptos.fast_multiply(cryptos.G, decoded_private_key)
print("Public Key (x,y) coordinates is:", public_key)

# Encode as hex, prefix 04
hex_encoded_public_key = cryptos.encode_pubkey(public_key, 'hex')
print("Public Key (hex) is:", hex_encoded_public_key)

# Compress public key, adjust prefix depending on whether y is even or odd
(public_key_x, public_key_y) = public_key
compressed_prefix = '02' if (public_key_y % 2) == 0 else '03'
hex_compressed_public_key = compressed_prefix + (cryptos.encode(public_key_x, 16).zfill(64))
print("Compressed Public Key (hex) is:", hex_compressed_public_key)

# Generate Bitcoin address from public key
print("Bitcoin Address (b58check) is:", cryptos.pubkey_to_address(public_key))

# Generate compressed Bitcoin address from compressed public key
print("Compressed Bitcoin Address (b58check) is:",
      cryptos.pubkey_to_address(hex_compressed_public_key))