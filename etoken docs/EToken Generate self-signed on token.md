# Step 1: Generate RSA key on the token
```
p11keygen -l /usr/lib/libeToken.so -k rsa -b 2048 -i flower-ca-root encrypt decrypt sign verify
```

# Step 2: Self-sign the certificate directly on the token
```
p11mkcert -l /usr/lib/libeToken.so \
-i flower-ca-root \
-d '/CN=FlowerCA/OU=certification/O=flower-org/C=SU' \
-H sha256
```

# Import self-signed certificate back to the token

```
$ p11importcert -l /usr/lib/libeToken.so -f flower-ca-root.crt -i flower-ca-root
```