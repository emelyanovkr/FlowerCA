Meaning of:
```
io.netty.handler.codec.DecoderException: 
javax.net.ssl.SSLHandshakeException: 
(certificate_required) Empty client certificate chain
```
on the server.

This might mean the root certificate is not a valid CA cert.
Which means it probably doesn't have field like
```
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
```

Check the root CA cert and make sure it is a valid CA cert with all the right permissions.
