# Admin mTLS API

FlowerCA exposes public and administrative routes on the shared HTTPS listener. The listener uses
`client-auth=want`: callers without a client certificate can reach public routes, while Spring
Security requires a database-authorized `ADMIN_CLIENT` certificate for `/api/v1/admin/**`.

Activate the `mtls` Spring profile and provide server identity and client trust material externally:

```shell
SPRING_PROFILES_ACTIVE=mtls
FLOWERCA_TLS_KEY_STORE=/run/secrets/flowerca-server.p12
FLOWERCA_TLS_KEY_STORE_PASSWORD=change-at-deployment
FLOWERCA_TLS_TRUST_STORE=/run/secrets/flowerca-admin-trust.p12
FLOWERCA_TLS_TRUST_STORE_PASSWORD=change-at-deployment
```

The server keystore contains the FlowerCA HTTPS server identity. It must not contain the online CA
signing key or an administrator identity. The truststore contains the CA certificate chain accepted
for client authentication, never a private key.

Public transport probe:

```shell
curl --cacert root-ca.cert.pem https://flowerca.example/api/v1/public/probe
```

Create an active ordinary user with the bootstrap administrator certificate and its local private
key:

```shell
curl --cacert root-ca.cert.pem \
  --cert first-admin.cert.pem \
  --key first-admin.key.pem \
  -H 'Content-Type: application/json' \
  -d '{"displayName":"Bob User","email":"bob@example.internal"}' \
  https://flowerca.example/api/v1/admin/users
```

The request cannot choose a role or status. This endpoint always creates `USER/ACTIVE`. It does not
issue a certificate; enrollment remains a separate operation.

TLS validates the certificate chain. Application authorization then requires the exact certificate
SHA-256 fingerprint in the database, matching issuer and serial, active/time-valid certificate and
issuer, `ADMIN_CLIENT` profile, and an active owner with role `ADMIN`. Subject CN is never used.

An unknown-CA certificate fails during TLS before Spring Security. No certificate or an unknown
database fingerprint receives `401`; a known active non-admin certificate receives `403`.
