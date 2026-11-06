from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15

# FIPS 197 AES-128 example exercises the compiled cipher implementation.
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
cipher = AES.new(key, AES.MODE_ECB)
assert cipher.encrypt(plaintext) == ciphertext
assert cipher.decrypt(ciphertext) == plaintext

message = SHA256.new(b"abc")
assert message.hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

rsa_key = RSA.generate(2048)
signature = pkcs1_15.new(rsa_key).sign(message)
pkcs1_15.new(rsa_key.public_key()).verify(message, signature)

ecc_key = ECC.generate(curve="P-256")
signature = DSS.new(ecc_key, "fips-186-3").sign(message)
DSS.new(ecc_key.public_key(), "fips-186-3").verify(message, signature)
