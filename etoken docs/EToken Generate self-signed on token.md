# Step 1: Generate RSA key on the token
```
p11keygen -l /usr/lib/libeToken.so -k rsa -b 2048 -i flower-ca-root-rsa-2048 sign verify
```

# Step 2: Self-sign the certificate directly from the token
```
p11req -l /usr/lib/libeToken.so \
-i flower-ca-root-rsa-2048 \
-d '/CN=FlowerCA/OU=certification/O=flower-org/C=SU' \
-H sha256 \
-s \
-o flower-ca-root.crt
```

# Step 3: Import the self-signed certificate back to the token
```
p11importcert -l /usr/lib/libeToken.so -f test-ca-root.crt -i flower-ca-root-rsa-2048
```
