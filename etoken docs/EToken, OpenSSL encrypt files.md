# This document is about encrypting files using pkcs#11 tokens.

## For MacOS use `--module /usr/local/lib/libeToken.dylib`


## Pkcs11: `pkcs11-tool` functions

### Get random data (sanity check test)

`pkcs11-tool --module /usr/lib/libeToken.so --login --generate-random 64 | xxd -c 64 -p`

### To list all objects on the smart card:

`pkcs11-tool --module /usr/lib/libeToken.so --login --list-objects`

### To see the list of functions supported by the keys

`pkcs11-tool --module /usr/lib/libeToken.so --login -t`

---
## Encrypt file and Decrypt via pkcs11-tool and token

- To enable this function we need to install private key via pkcs11-tool, not with SafeNet tools. That's because SafeNet tools create private keys with limited privileges:
  `Usage:  sign`
  while we need more extensive functionality, like:
  `Usage:  decrypt, sign, unwrap`

- We encrypt using openssl, and we decrypt using our token. Maybe some versions of `pkcs11-tool` on some operating systems support both encrypt and decrypt, and work fine, but I wasn't able to find such instances. Instead of theorizing on that topic, this tutorial describes what actually works.


### Create keys/certificate and write it to the token using pkcs11-tool

Certificate creation process is the same as described in the document `EToken, certificates, ssh`.

After keys and certificate have been created, we need to do the following steps (some of which are described here https://sztsian.github.io/2022/03/12/Generate-Key-Pair-With-OpenSSL-And-Import-To-PKCS11-Token.html)

Let's say, we have the following files under `easy-rsa` directory:
```
pki/private/meinung-data.key
pki/reqs/meinung-data.req
pki/issued/meinung-data.crt
```

1. Convert private key to DER format:
   `openssl rsa -in pki/private/meinung-data.key -outform DER -out meinung-data-key.der`

2. Convert certificate to DER format:
   `openssl x509 -outform DER -in pki/issued/meinung-data.crt -out meinung-data-crt.der`

3. Extract public key from .key file:
   `openssl rsa -in pki/private/meinung-data.key -pubout -out meinung-data-public.key`

4. Write those files to the token
```
pkcs11-tool --module /usr/lib/libeToken.so --login --write-object meinung-data-key.der --type privkey --id 1
pkcs11-tool --module /usr/lib/libeToken.so --login --write-object meinung-data-crt.der --type cert --id 1
pkcs11-tool --module /usr/lib/libeToken.so --login --write-object meinung-data-public.key --type pubkey --id 1
```

### Encrypt data using public key and openssl, and decrypt it with pkcs11-tool using token

#### We extract the certificate/public key from token to make it portable

1. Create a data file to encrypt, e.g.
   `echo "Datum to encrypt should be longer, better, faster and whatever we need to hide in front of nasty eyes of the ones that should not see them. " > data`

2. Get the certificate from the card:
   `pkcs11-tool --module /usr/lib/libeToken.so -r --id 1 --type cert > meinung-data.cert`


3. Convert certificate to public key (PEM format)
   `openssl x509 -inform DER -in meinung-data.cert -pubkey > meinung-data.pub`


4. Encrypt file usen openssl
   `openssl rsautl -encrypt -inkey meinung-data.pub -in data -pubin -out data.crypt`


5. Decrypt file using eToken
   `pkcs11-tool --module /usr/lib/libeToken.so --login --id 1 --decrypt -i data.crypt -o data.new -m RSA-PKCS`


## WIPE (not delete) files
```
wipe pki/private/meinung-data.key
wipe pki/reqs/meinung-data.req
wipe pki/issued/meinung-data.crt
wipe meinung-data.cert
wipe meinung-data-crt.der
wipe meinung-data-key.der
wipe meinung-data.pub
wipe meinung-data.public.key
wipe meinung-data.pem
wipe meinung-data.pfx
```

## Trying the same with AES-256

For some reason none of symmetric encryption functions work on my token, all failing with error `CKR_TEMPLATE_INCONSISTENT` - key generation, key import, etc.

The link below suggests that it's related to some eToken settings.
https://stackoverflow.com/questions/52103989/how-to-set-create-a-key-value-for-aes-secret-key-on-network-luna-hsm

> Apparently, after speaking with Gemalto and several comments, this cannot be done on the non-protectserver family of Network HSMs. The process works perfectly for the protect server HSMs (They now have a protect server Network HSM). After updating my unwrapping process to use the CBC mode with an IV, I was able to create the keys but not with specified key values..

**"Non-protectserver family of Network HSMs"** ^ sounds like a pile of crap nobody should be required to know anything about.
So my opinion is - to hell with it. I'll use whatever works as expected and follows the standards.