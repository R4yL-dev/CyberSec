import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def main():
    ciphertext_b64 = b"Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug31opX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe"
    key = b"my-secret-key-16"

    ciphertext = base64.b64decode(ciphertext_b64)

    print("-- CipherText --")
    print(f"{ciphertext}")
    print("\n-- KEY --")
    print(key)
    
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    print("\n-- PlainText --")
    print(plaintext)

if __name__ == "__main__":
    main()
