package com.fidd.flowerca.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.fidd.flowerca.api.admin.CreateUserRequest;
import com.fidd.flowerca.api.admin.RenewAdminCertificateRequest;
import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import com.fidd.flowerca.testsupport.TlsTestClient;
import com.fidd.flowerca.testsupport.TlsTestClient.Identity;
import com.fidd.flowerca.testsupport.TlsTestMaterial;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

// Docker required. No MockMvc, replacement security beans, or manually injected request certificates.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "flowerca.issuer.enabled=true", "server.address=127.0.0.1"})
@ActiveProfiles("mtls")
@Import(MySqlTestcontainerConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class MtlsTransportIntegrationTests {

  private static TlsTestMaterial material;
  @LocalServerPort private int port;
  @Autowired private ObjectMapper json;
  @Autowired private UserProfileRepository users;
  @Autowired private CertificateRepository certificates;
  @Autowired private AuditEventRepository audit;
  @Autowired private CertificateIssuanceService issuance;
  @Autowired private CertificateIssuer certificateIssuer;
  @Autowired private CsrParser parser;

  private UserProfileEntity admin;
  private CertificateEntity adminRecord;
  private Identity adminIdentity;
  private Identity userIdentity;
  private Identity unregisteredIdentity;
  private Identity foreignIdentity;
  private TestPki foreignPki;

  @DynamicPropertySource
  static void tlsProperties(DynamicPropertyRegistry properties) throws Exception {
    material = TlsTestMaterial.create();
    // Supply the SAME external inputs consumed by application-mtls.yaml, not an alternative profile.
    properties.add("FLOWERCA_TLS_KEY_STORE", () -> material.path("server.p12").toUri().toString());
    properties.add("FLOWERCA_TLS_KEY_STORE_PASSWORD", material::password);
    properties.add("FLOWERCA_TLS_TRUST_STORE", () -> material.path("client-trust.p12").toUri().toString());
    properties.add("FLOWERCA_TLS_TRUST_STORE_PASSWORD", material::password);
    properties.add("flowerca.issuer.key-store", () -> material.path("issuer.p12").toUri().toString());
    properties.add("flowerca.issuer.alias", () -> "test-issuer");
    properties.add("flowerca.issuer.password", material::password);
    properties.add("flowerca.issuer.trusted-root", () -> material.path("root.pem").toUri().toString());
    // Do not print a generated fallback Spring login password; form/basic authentication stay disabled.
    properties.add("spring.security.user.password", material::password);
  }

  @BeforeAll
  void prepareClientIdentities() throws Exception {
    admin = users.saveAndFlush(new UserProfileEntity("TLS Admin", uniqueEmail(), UserRole.ADMIN));
    KeyPair adminKeys = TlsTestMaterial.newKeyPair();
    var adminIssued = issuance.issueAdminClient(TestPki.createCsrPem(adminKeys, "ignored.internal"), admin);
    adminRecord = certificates.findById(adminIssued.certificateId()).orElseThrow();
    adminIdentity = new Identity(adminKeys.getPrivate(), adminIssued.issuedCertificate().fullChain());

    var user = users.saveAndFlush(new UserProfileEntity("TLS User", uniqueEmail(), UserRole.USER));
    KeyPair userKeys = TlsTestMaterial.newKeyPair();
    var userIssued = issuance.issueUserClient(TestPki.createCsrPem(userKeys, "ignored.internal"), user);
    userIdentity = new Identity(userKeys.getPrivate(), userIssued.issuedCertificate().fullChain());

    KeyPair unknownKeys = TlsTestMaterial.newKeyPair();
    // Deliberately claim the SAME approved identity as the admin, but do not register this certificate.
    var unknown = certificateIssuer.issue(parser.parse(TestPki.createCsrPem(unknownKeys, "ignored.internal")),
        CertificateProfile.ADMIN_CLIENT,
        new CertificateIdentity.User(admin.getId(), admin.getDisplayName(), admin.getEmail()));
    unregisteredIdentity = new Identity(unknownKeys.getPrivate(), unknown.fullChain());

    foreignPki = TestPki.create();
    var foreign = new CertificateIssuer(foreignPki.issuerIdentity(), new InternalCertificatePolicy())
        .issue(parser.parse(foreignPki.createCsrPem("ignored.internal")), CertificateProfile.ADMIN_CLIENT,
            new CertificateIdentity.User(UUID.randomUUID(), "Foreign Admin", uniqueEmail()));
    foreignIdentity = new Identity(foreignPki.clientKeyPair().getPrivate(), foreign.fullChain());
  }

  @AfterAll
  static void removeTemporaryMaterial() throws Exception {
    if (material != null) {
      material.close();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void noClientCertificateCanReachPublicProbe(String protocol) throws Exception {
    try (var client = client(protocol, null)) {
      var response = getProbe(client, "localhost");
      assertHandshake(response, protocol, null);
      assertThat(response.statusCode()).isEqualTo(200);
      assertThat(json.readTree(response.body()).get("status").stringValue()).isEqualTo("ok");
      assertThat(client.serverTrusted()).isTrue();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void noClientCertificateIsDeniedByApplicationNotTls(String protocol) throws Exception {
    try (var client = client(protocol, null)) {
      var response = post(client, "/api/v1/admin/users", new CreateUserRequest("Denied", uniqueEmail()));
      assertHandshake(response, protocol, null);
      assertError(response, 401, "UNAUTHORIZED", "Authentication required");
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void adminCertificateCreatesUserAndAuditsRealTransportIdentity(String protocol) throws Exception {
    String email = uniqueEmail();
    try (var client = client(protocol, adminIdentity)) {
      var response = post(client, "/api/v1/admin/users", new CreateUserRequest("Created over TLS", email));
      assertHandshake(response, protocol, adminIdentity);
      assertThat(response.statusCode()).isEqualTo(201);
      assertThat(json.readTree(response.body()).get("role").stringValue()).isEqualTo("USER");
    }
    var created = users.findByEmailIgnoreCase(email).orElseThrow();
    assertThat(audit.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(AuditTargetType.USER_PROFILE, created.getId()))
        .singleElement().satisfies(event -> {
          assertThat(event.getAction()).isEqualTo(AuditAction.USER_CREATED);
          assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
          assertThat(event.getActorProfileId()).isEqualTo(admin.getId());
          assertThat(event.getActorCertificateId()).isEqualTo(adminRecord.getId());
          assertThat(event.getActorCertificateFingerprintSha256()).isEqualTo(adminRecord.getFingerprintSha256());
        });
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void registeredOrdinaryUserPassesTlsButNotAdminAuthorization(String protocol) throws Exception {
    String email = uniqueEmail();
    try (var client = client(protocol, userIdentity)) {
      var response = post(client, "/api/v1/admin/users", new CreateUserRequest("Denied", email));
      assertHandshake(response, protocol, userIdentity);
      assertError(response, 403, "FORBIDDEN", "Access denied");
    }
    assertThat(users.findByEmailIgnoreCase(email)).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void sameAdminSubjectAndSanWithoutRegisteredFingerprintIsDenied(String protocol) throws Exception {
    try (var client = client(protocol, unregisteredIdentity)) {
      var response = post(client, "/api/v1/admin/users", new CreateUserRequest("Denied", uniqueEmail()));
      assertHandshake(response, protocol, unregisteredIdentity);
      assertError(response, 401, "UNAUTHORIZED", "Authentication required");
    }
    assertThat(unregisteredIdentity.chain().getFirst().getSubjectX500Principal())
        .isEqualTo(adminIdentity.chain().getFirst().getSubjectX500Principal());
    assertThat(List.copyOf(unregisteredIdentity.chain().getFirst().getSubjectAlternativeNames()))
        .isEqualTo(List.copyOf(adminIdentity.chain().getFirst().getSubjectAlternativeNames()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void actuallyPresentedForeignCaCertificateFailsEvenOnPublicRoute(String protocol) throws Exception {
    try (var client = client(protocol, foreignIdentity)) {
      Throwable failure = catchThrowable(() -> getProbe(client, "localhost"));
      assertTlsFailure(failure);
      assertThat(client.serverTrusted()).isTrue();
      assertThat(client.identitySelections()).isPositive();
      assertThat(client.chainReads()).isPositive();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void adminCertificateWithUnrelatedPrivateKeyCannotAuthenticate(String protocol) throws Exception {
    Identity wrongKey = new Identity(TlsTestMaterial.newKeyPair().getPrivate(), adminIdentity.chain());
    String email = uniqueEmail();
    try (var client = client(protocol, wrongKey)) {
      Throwable failure = catchThrowable(() -> post(client, "/api/v1/admin/users", new CreateUserRequest("Denied", email)));
      assertTlsFailure(failure);
      assertThat(client.serverTrusted()).isTrue();
      assertThat(client.identitySelections()).isPositive();
      assertThat(client.chainReads()).isPositive();
    }
    assertThat(users.findByEmailIgnoreCase(email)).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void clientRejectsUntrustedServerCa(String protocol) throws Exception {
    try (var client = new TlsTestClient(protocol, foreignPki.rootCertificate(), null)) {
      assertTlsFailure(catchThrowable(() -> getProbe(client, "localhost")));
      assertThat(client.serverTrusted()).isFalse();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void clientRejectsServerHostnameMismatch(String protocol) throws Exception {
    // Fixture has only DNS SAN localhost, deliberately no IP SAN 127.0.0.1.
    try (var client = client(protocol, null)) {
      assertTlsFailure(catchThrowable(() -> getProbe(client, "127.0.0.1")));
      assertThat(client.serverTrusted()).isFalse();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"TLSv1.3"})
  void renewedCertificateWorksOverNewTlsConnection(String protocol) throws Exception {
    KeyPair keys = TlsTestMaterial.newKeyPair();
    UUID newId;
    Identity renewedIdentity;
    try (var client = client(protocol, adminIdentity)) {
      var response = post(client, "/api/v1/admin/certificates/renew",
          new RenewAdminCertificateRequest(TestPki.createCsrPem(keys, "ignored.internal")));
      assertHandshake(response, protocol, adminIdentity);
      assertThat(response.statusCode()).isEqualTo(200);
      var body = json.readTree(response.body());
      newId = UUID.fromString(body.get("certificateId").stringValue());
      var chain = CertificateFactory.getInstance("X.509").generateCertificates(
          new ByteArrayInputStream(body.get("certificateChainPem").stringValue().getBytes(StandardCharsets.US_ASCII)))
          .stream().map(certificate -> (X509Certificate) certificate).toList();
      renewedIdentity = new Identity(keys.getPrivate(), chain);
    }
    assertThat(certificates.findAllByUserProfile_IdAndStatus(admin.getId(), CertificateStatus.ACTIVE))
        .extracting(CertificateEntity::getId).contains(adminRecord.getId(), newId);
    assertThat(audit.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(AuditTargetType.CERTIFICATE, newId))
        .anySatisfy(event -> {
          assertThat(event.getAction()).isEqualTo(AuditAction.ADMIN_CERTIFICATE_RENEWED);
          assertThat(event.getActorCertificateId()).isEqualTo(adminRecord.getId());
          assertThat(event.getActorCertificateFingerprintSha256()).isEqualTo(adminRecord.getFingerprintSha256());
        });
    try (var client = client(protocol, renewedIdentity)) {
      var response = post(client, "/api/v1/admin/users", new CreateUserRequest("Renewed TLS Admin", uniqueEmail()));
      assertHandshake(response, protocol, renewedIdentity);
      assertThat(response.statusCode()).isEqualTo(201);
    }
  }

  private TlsTestClient client(String protocol, Identity identity) throws Exception {
    return new TlsTestClient(protocol, material.pki().rootCertificate(), identity);
  }

  private HttpResponse<String> getProbe(TlsTestClient client, String host) throws Exception {
    var request = HttpRequest.newBuilder(URI.create("https://" + host + ":" + port + "/api/v1/public/probe"))
        .timeout(Duration.ofSeconds(15)).GET().build();
    return client.http().send(request, HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> post(TlsTestClient client, String path, Object body) throws Exception {
    var request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + path))
        .timeout(Duration.ofSeconds(15)).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body))).build();
    return client.http().send(request, HttpResponse.BodyHandlers.ofString());
  }

  private void assertHandshake(HttpResponse<String> response, String protocol, Identity identity) throws Exception {
    var session = response.sslSession().orElseThrow();
    assertThat(session.getProtocol()).isEqualTo(protocol);
    if (identity == null) {
      assertThat(session.getLocalCertificates()).isNullOrEmpty();
    } else {
      assertThat(session.getLocalCertificates()).isNotEmpty();
      assertThat(session.getLocalCertificates()[0].getEncoded()).isEqualTo(identity.chain().getFirst().getEncoded());
    }
  }

  private void assertError(HttpResponse<String> response, int status, String code, String message) throws Exception {
    assertThat(response.statusCode()).isEqualTo(status);
    assertThat(json.readTree(response.body())).isEqualTo(json.readTree(json.writeValueAsString(
        java.util.Map.of("code", code, "message", message))));
  }

  private void assertTlsFailure(Throwable failure) {
    assertThat(failure).isInstanceOf(IOException.class);
    List<Throwable> causes = new ArrayList<>();
    for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
      causes.add(cause);
    }
    assertThat(causes).anyMatch(SSLException.class::isInstance);
  }

  private String uniqueEmail() { return "tls-" + UUID.randomUUID() + "@example.internal"; }
}
