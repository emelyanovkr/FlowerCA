https://github.com/Mastercard/pkcs11-tools  
https://github.com/Mastercard/pkcs11-tools/releases  
https://github.com/Mastercard/pkcs11-tools/blob/master/docs/MANUAL.md#p11importcert  
https://github.com/Mastercard/pkcs11-tools/blob/master/docs/INSTALL.md  

# EToken: Generate keys on token and run CSR 
All done with MaterCard's `pkcs11-tools`, not to be confused with `pkcs11-tool`.

The idea is to generate private key right on the token, so it doesn't get exposed ever at all anywhere or copied. It sits on the token once generated and can only be used via PKCS#11.
Obviously, this approach has its drawbacks, because the key will be lost with token and can't be recovered.  
Thus, it's not advisable to use it for cryptocurrency account private keys or similar applications where the private key is not replaceable, and it's highly desirable to be able to preserve it indefinitely. And even in other applications you need to design your routines around this fact, with key deprecation and rotation built-in, and/or backup keys.  
But other than that, it's the most secure way to store and use private keys I know of.

Here's how it's done:

---
1. Generate key on the token:  
`p11keygen -l /usr/local/lib/libeToken.dylib -k rsa -b 2048 -i test-rsa-2048 encrypt decrypt sign verify`
`p11keygen -l /usr/lib/libeToken.so -k rsa -b 2048 -i test-rsa-2048 encrypt decrypt sign verify`

2. Create CSR request from the token:  
`p11req -l /usr/local/lib/libeToken.dylib -i test-rsa-2048 -d '/CN=test/OU=my dept/C=BE' -H sha256 -e DNS:anotherhost.int -e email:writeme\@mastercard.com`
`p11req -l /usr/lib/libeToken.so -i test-rsa-2048 -d '/CN=test/OU=my dept/C=BE' -H sha256 -e DNS:anotherhost.int -e email:writeme\@mastercard.com`


3. Import certificate signed by our CA back to the token:  
```
$ p11importcert -l /usr/local/lib/libeToken.dylib -f test.crt -i test-rsa-2048
PEM format detected
p11importcert: importing certificate succeeded.
```
```
$ p11importcert -l /usr/lib/libeToken.so -f test.crt -i test-rsa-2048
```
cer to pub
```
openssl x509 -pubkey -noout -in MY.crt > MY.pem
ssh-keygen -f MY.pem -i -m PKCS8 > MY.openssh.pub
```

DONE!
