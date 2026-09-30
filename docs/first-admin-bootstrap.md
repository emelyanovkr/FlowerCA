# First administrator bootstrap

The first administrator is created once, before the admin mTLS API is enabled. The administrator
generates the private key locally. FlowerCA receives only the public-key CSR and never stores or
returns the private key.

## 1. Generate the private key and CSR on the administrator workstation

```shell
openssl req -new -newkey rsa:3072 -noenc \
  -keyout first-admin.key.pem \
  -out first-admin.csr.pem \
  -subj "/CN=ignored-csr-identity"
```

Protect `first-admin.key.pem`. Copy only `first-admin.csr.pem` to the FlowerCA host.

## 2. Run one FlowerCA instance in bootstrap mode

Bootstrap is disabled by default. Configure the Intermediate CA normally, then set:

```shell
FLOWERCA_BOOTSTRAP_ADMIN_ENABLED=true
FLOWERCA_BOOTSTRAP_ADMIN_DISPLAY_NAME=Alice Admin
FLOWERCA_BOOTSTRAP_ADMIN_EMAIL=alice@example.internal
FLOWERCA_BOOTSTRAP_ADMIN_CSR_PATH=/run/secrets/first-admin.csr.pem
FLOWERCA_BOOTSTRAP_ADMIN_CERTIFICATE_CHAIN_OUTPUT=/run/flowerca/first-admin.chain.pem
```

The CSR file and output directory must already exist and be readable/writable by the FlowerCA
process. Start only one bootstrap instance. In one database transaction FlowerCA registers the
configured Intermediate if needed, creates the active ADMIN profile, signs and persists an active
ADMIN_CLIENT certificate linked to that profile, writes the issuance audit event, and completes the
single `first-admin` bootstrap marker.

The PEM output contains the leaf certificate followed by its issuer chain. It contains no private
key. Copy it to the administrator workstation and disable bootstrap immediately:

```shell
FLOWERCA_BOOTSTRAP_ADMIN_ENABLED=false
```

The CSR and certificate output may then be removed from the FlowerCA host according to the
deployment's secret-file policy. The private key remains only on the administrator workstation or
hardware token.

## 3. Verify the certificate

The first certificate in `first-admin.chain.pem` is the admin leaf. Inspect its identity and client
authentication purpose:

```shell
openssl x509 -in first-admin.chain.pem -noout -subject -issuer -serial -dates -text
```

Verify the chain and `sslclient` purpose using the separately trusted Root certificate:

```shell
openssl verify -purpose sslclient \
  -CAfile root-ca.cert.pem \
  -untrusted first-admin.chain.pem \
  first-admin.chain.pem
```

The leaf must contain `TLS Web Client Authentication`, URI SAN
`urn:flowerca:user:<profile-uuid>`, and the configured email SAN. CSR Subject and SAN claims are
ignored.

## Recovery

- If signing occurred in memory but the database transaction failed, no certificate or bootstrap
  marker is committed and no certificate is returned. Fix the database/audit failure and rerun with
  the same identity and CSR.
- If the database committed but writing the PEM output failed, fix the output directory and rerun
  with exactly the same identity and CSR. FlowerCA exports the already-persisted certificate and
  does not issue another one.
- If a completed marker exists but the configured identity or CSR differs, startup fails. FlowerCA
  never silently replaces or rotates the first administrator. Recover the original private key/CSR
  or perform an explicitly reviewed database recovery; do not delete bootstrap state casually.
