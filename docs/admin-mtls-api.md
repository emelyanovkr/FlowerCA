# Admin mTLS API

Пошаговое объяснение на примере Анны и Бориса, схема взаимодействия и структура
SecurityContext: [Как работает административный mTLS endpoint](admin-mtls-flow.md).

План следующих маршрутов и инкрементов: [API заявок и сертификатов](certificate-request-api-plan.md).

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

## Read the certificate registry

`GET /api/v1/admin/certificates` and `GET /api/v1/admin/certificates/{id}` require the same
registered active admin identity as other admin routes, plus service-level `ADMIN` method security.
List, detail and renewal live in one `AdminCertificateController` / `AdminCertificateService`.
There is no separate read-only operating mode: `flowerca.issuer.enabled=false` disables all
certificate admin routes. Normal operation requires the configured Intermediate signing module.
Reads return registry metadata, not certificate DER/PEM or private keys.
The list covers all certificate profiles and owners; it is not limited to the caller's certificates.

List query parameters:

| Parameter | Meaning / default |
| --- | --- |
| `ownerId` | Optional user-profile UUID |
| `profile` | Optional `TLS_SERVER`, `USER_CLIENT`, `ADMIN_CLIENT` |
| `effectiveStatus` | Optional `ACTIVE`, `NOT_YET_VALID`, `EXPIRED`, `REVOKED` |
| `page` | Zero-based page, default `0` |
| `size` | `1..100`, default `50` |
| `sort` | Standard Spring `Pageable` sorting, default `createdAt,desc` |

The controller accepts `Pageable`; Spring resolves `page`, `size`, `sort` from query parameters.
Allowed sort fields: `createdAt`, `notBefore`, `notAfter`, `id`; directions: `asc`, `desc`.
An omitted direction means ascending; repeated sort parameters are supported, e.g.
`sort=notAfter,asc&sort=createdAt,desc`. At most four sort orders, no ignore-case/null-order modifiers.
Unless ID is already present, an ID tie-breaker uses the first order's direction.
The certificate-specific resolver rejects invalid/duplicate numeric page/size values with 400
instead of silently replacing or clamping them; the service also validates direct Java input.
Blank numeric parameters use defaults. Pagination uses offset; changes to the registry
between HTTP requests can move records between pages. Excessive integer offsets are rejected.

```shell
curl --cacert root-ca.cert.pem \
  --cert first-admin.chain.pem --key first-admin.key.pem \
  'https://flowerca.example/api/v1/admin/certificates?profile=USER_CLIENT&effectiveStatus=ACTIVE&page=0&size=50&sort=notAfter,asc'
```

The stable page envelope is `content`, `page`, `size`, `totalElements`, `totalPages`.
An empty/out-of-range page returns `200` with empty content and the matching total.
Each list item and detail contains `id`, `owner` (`id`, `displayName`, `email`) or null for an
ownerless server certificate, `issuer` (`id`, `subjectDn`), `serialNumberHex`,
`fingerprintSha256Hex`, `profile`, `storedStatus`, `effectiveStatus`, `subjectDn`,
`notBefore`, `notAfter`, `revokedAt`, `revocationReason`, `createdAt`.
Hex is lowercase; serial is unsigned without padding, SHA-256 fingerprint has 64 digits.
Owner name/email are current profile metadata; `subjectDn` is the identity stored at issuance.

Effective status is evaluated at one instant per request: stored `REVOKED` takes precedence;
stored `EXPIRED` or `now >= notAfter` yields `EXPIRED`; otherwise `now < notBefore` yields
`NOT_YET_VALID`, and the remaining certificate is `ACTIVE`. Reads never update stored status.
This describes the certificate's lifecycle, not whether its owner/issuer is authorized to log in.
DTO queries live in the shared `CertificateRepository` as JPQL constructor projections, not
entity fetches. Spring Data may omit a count query when the returned page already proves the total.
Invalid parameters/UUID -> constant `400 INVALID_REQUEST`; unknown certificate -> constant
`404 NOT_FOUND`. No certificate -> `401`, known non-admin identity -> `403`.
PEM download and revocation remain separate planned increments.

## Renew the current administrator certificate

Before the current certificate expires, generate a new key and CSR on the administrator's
workstation. Keep both private keys on that workstation (or hardware token); submit only the CSR.

```shell
openssl req -new -newkey rsa:3072 -noenc \
  -keyout renewed-admin.key.pem -out renewed-admin.csr.pem \
  -subj "/CN=ignored-csr-identity"
jq -n --rawfile csr renewed-admin.csr.pem '{csrPem: $csr}' > renewal-request.json
curl --cacert root-ca.cert.pem \
  --cert first-admin.chain.pem --key first-admin.key.pem \
  -H 'Content-Type: application/json' --data-binary @renewal-request.json \
  https://flowerca.example/api/v1/admin/certificates/renew \
  > renewal-response.json
jq -r '.certificateChainPem' renewal-response.json > renewed-admin.chain.pem
```

Check the HTTP status before extracting a certificate. A successful `200` response contains
`certificateId`, `notBefore`, `notAfter`, and `certificateChainPem` (leaf followed by issuer chain).
Verify the new chain and `sslclient` purpose as in the bootstrap guide, then test it with the
protected admin API before switching clients. The old certificate remains valid until its expiry
unless revoked separately; renewal does not revoke it. Each successful request issues a new
certificate; retries are not idempotent and also issue a new certificate.

The request has only `csrPem`, bounded to 65,536 characters. It cannot select an owner, role, or
certificate profile. Identity is rebuilt from the same approved administrator profile. The service
requires `ADMIN` authority even when invoked from Java, rechecks and locks the current database
owner/certificate, and commits the new certificate plus `CERTIFICATE_ISSUED` and actor-attributed
`ADMIN_CERTIFICATE_RENEWED` audits together before the controller can return success.

Profile lifetimes are independently configurable. Defaults remain 30 days for all three profiles:

```yaml
flowerca:
  certificates:
    lifetime:
      tls-server: 30d
      user-client: 30d
      admin-client: 30d
```

Positive lifetimes of at least one second and at most 3,650 days are accepted. Actual expiry is
always capped by the configured Intermediate CA expiry; increasing a profile lifetime cannot
extend the Intermediate. Inspect `notAfter` and renew with enough margin. An immediate renewal
with an unchanged lifetime need not increase expiry materially.

Expired/revoked certificates cannot renew. An expired bootstrap certificate is not re-exported as
success. Operator recovery after expiry or loss of the private key is deliberately not implemented
yet; the renewal endpoint is not a recovery backdoor.

## Error handling and verification limits

Unavailable certificate-registry database access returns constant `503 SERVICE_UNAVAILABLE`, not
`401`. Unexpected authentication failures return constant `500 INTERNAL_ERROR`. Public routes do
not query the certificate registry, even if a client certificate is supplied. TLS chain validation
still happens first and can reject an untrusted certificate on a public route.

MVC errors preserve their HTTP meaning: malformed/invalid input `400`, missing route `404`, wrong
method `405` (including `Allow`), unsupported request media type `415`, duplicate user `409`, and
unexpected application failures `500`. Public bodies never include technical exception details.

## Automatic HTTPS/mTLS verification

`MtlsTransportIntegrationTests` starts the real embedded Tomcat server on a random loopback HTTPS
port with the `mtls` profile. It supplies temporary server and issuer PKCS#12 identities and a
client-CA truststore through the same external settings used by deployments. No MockMvc request
certificate injection, replacement security beans, or alternative TLS configuration is used.
Production issuer loading, registration, application services, persistence and security are exercised
against the existing MySQL Testcontainer. Docker must be running.

On Windows, run just the transport tests:

```powershell
.\gradlew.bat test --tests '*MtlsTransportIntegrationTests'
```

Or run the full suite with `.\gradlew.bat test` (`./gradlew test` on Linux).
Each of the ten scenarios runs only for TLS 1.3, and successful responses must report TLS 1.3
as the negotiated protocol. The application still enables TLS 1.2, but the regular transport
suite no longer verifies it; success on TLS 1.3 does not prove TLS 1.2 compatibility:

| Scenario | Expected result |
| --- | --- |
| No client certificate, public probe | HTTPS succeeds, HTTP 200 |
| No client certificate, admin API | HTTPS succeeds, HTTP 401 |
| Registered ADMIN_CLIENT, active admin owner | HTTP 201; created user and actor-attributed audit committed |
| Registered USER_CLIENT | HTTPS succeeds, HTTP 403; no user created |
| Trusted unregistered certificate copying admin CN and SAN | HTTPS succeeds, HTTP 401 |
| Actually presented client certificate signed by a foreign CA, even on public route | TLS failure, no HTTP response |
| Admin certificate paired with an unrelated private key | TLS failure, no HTTP response or user creation |
| Client does not trust server CA | TLS failure |
| Client requests 127.0.0.1 while server certificate has only localhost DNS SAN | TLS hostname verification failure |
| Admin renewal followed by a fresh connection using the new key/certificate | HTTP 200 renewal, committed audit, then HTTP 201 using renewed identity |

Every test client has a fresh SSLContext to avoid TLS-session reuse hiding the handshake. Clients
use the standard validating Java trust manager and HTTPS hostname verification, never trust-all
or disabled hostname checks. A test-only key manager explicitly selects the configured client
identity regardless of the advertised CA list, preventing the foreign-CA case from silently
omitting its certificate under `client-auth=want`. The rejection tests additionally verify that
server trust validation succeeded and client identity/chain were selected before the TLS failure.

All material is development-only. The localhost server fixture does not broaden FlowerCA's
production `.internal` DNS policy. The server identity, Intermediate signing identity and client
keys are separate; client keys stay in the test client, and no Root private key enters a server
keystore. Temporary PKCS#12 files use a randomly generated test password and are removed after
the class; a JVM shutdown fallback handles early Spring initialization failures. No generated
material is stored in Git.

Verified after narrowing on 2026-10-03: 10 TLS 1.3 transport tests and 90 full-suite tests passed,
0 failures, 0 errors, 0 skipped, with Docker/MySQL Testcontainers.

Historical verification on 2026-10-03, before narrowing the suite to TLS 1.3: 20 transport tests
passed for TLS 1.2/1.3, no failures/errors/skips; the full suite passed 100 tests. This is not
ongoing TLS 1.2 coverage. Existing MockMvc tests remain useful for application cases;
they are not used as evidence of TLS transport. This verifies embedded Tomcat locally, not a
deployment proxy/load balancer, a production truststore, or a dedicated admin connector. Manual
OpenSSL/curl checks against a deployment remain optional operational smoke checks.
