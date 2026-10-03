package com.fidd.flowerca.api.admin;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.*;
import com.fidd.flowerca.persistence.repository.*;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.security.ClientCertificateAuthenticationFilter;
import com.fidd.flowerca.security.ClientCertificatePrincipal;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.service.admin.AdminCertificateRenewalUseCase;
import com.fidd.flowerca.service.admin.RenewAdminCertificateCommand;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

// Docker required. No replacement issuer/service/registration beans: use production wiring.
@SpringBootTest(properties = {
    "flowerca.issuer.enabled=true", "flowerca.certificates.lifetime.admin-client=45d"})
@AutoConfigureMockMvc
@Import(MySqlTestcontainerConfiguration.class)
class AdminCertificateRenewalIntegrationTests {

  private static final String ROUTE = "/api/v1/admin/certificates/renew";
  private static TestPki pki;
  private static Path materialDirectory;

  @Autowired private MockMvc mvc;
  @Autowired private ObjectMapper json;
  @Autowired private UserProfileRepository users;
  @Autowired private CertificateRepository certificates;
  @MockitoSpyBean private AuditEventRepository audit;
  @Autowired private CertificateIssuanceService issuance;
  @Autowired private IssuedCertificatePersistenceService persistence;
  @Autowired private IssuerIdentity issuer;
  @Autowired private AdminCertificateRenewalUseCase renewal;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private FilterRegistrationBean<ClientCertificateAuthenticationFilter> registration;

  private UserProfileEntity admin;
  private CertificateEntity oldRecord;
  private X509Certificate oldCertificate;

  @DynamicPropertySource
  static void material(DynamicPropertyRegistry properties) throws Exception {
    pki = TestPki.create();
    materialDirectory = Files.createTempDirectory("flowerca-renewal-test-");
    var store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry("test-issuer", pki.issuerIdentity().privateKey(), "test-only".toCharArray(),
        pki.issuerIdentity().chain().toArray(Certificate[]::new));
    Path keyStore = materialDirectory.resolve("intermediate.p12");
    try (var output = Files.newOutputStream(keyStore)) {
      store.store(output, "test-only".toCharArray());
    }
    Path root = materialDirectory.resolve("root.pem");
    Files.write(root, new CertificateChainPemEncoder().encode(List.of(pki.rootCertificate())));
    properties.add("flowerca.issuer.key-store", () -> keyStore.toUri().toString());
    properties.add("flowerca.issuer.alias", () -> "test-issuer");
    properties.add("flowerca.issuer.password", () -> "test-only");
    properties.add("flowerca.issuer.trusted-root", () -> root.toUri().toString());
  }

  @AfterAll
  static void removeTestMaterial() throws Exception {
    if (materialDirectory != null) {
      Files.deleteIfExists(materialDirectory.resolve("intermediate.p12"));
      Files.deleteIfExists(materialDirectory.resolve("root.pem"));
      Files.deleteIfExists(materialDirectory);
    }
  }

  @BeforeEach
  void prepareAdmin() throws Exception {
    admin = users.saveAndFlush(new UserProfileEntity(
        "Renewal Admin", "renew-" + UUID.randomUUID() + "@example.internal", UserRole.ADMIN));
    // Existing 30-day certificate; production renewal uses the configured 45-day profile.
    var old = new CertificateIssuer(issuer, new InternalCertificatePolicy()).issue(
        new CsrParser().parse(pki.createCsrPem("spoofed.internal")),
        CertificateProfile.ADMIN_CLIENT,
        new CertificateIdentity.User(admin.getId(), admin.getDisplayName(), admin.getEmail()));
    oldRecord = persistence.persist(issuer, old, admin);
    oldCertificate = old.certificate();
  }

  @AfterEach
  void clear() {
    reset(audit);
    SecurityContextHolder.clearContext();
  }

  @Test
  void renewalPersistsNewKeyForSameAdminAuditsActorAndBothCertificatesWork() throws Exception {
    long profilesBefore = users.count();
    TestPki rotatedKeys = TestPki.create();
    String response = request(json.writeValueAsString(
        new RenewAdminCertificateRequest(rotatedKeys.createCsrPem("attacker.internal"))))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    var body = json.readTree(response);
    UUID newId = UUID.fromString(body.get("certificateId").asText());
    var chain = CertificateFactory.getInstance("X.509").generateCertificates(
        new ByteArrayInputStream(body.get("certificateChainPem").asText().getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    X509Certificate renewed = (X509Certificate) chain.iterator().next();
    assertThat(chain).hasSize(3);
    renewed.verify(issuer.certificate().getPublicKey());
    renewed.checkValidity();
    assertThat(renewed.getPublicKey().getEncoded()).isEqualTo(rotatedKeys.clientKeyPair().getPublic().getEncoded());
    assertThat(renewed.getPublicKey().getEncoded()).isNotEqualTo(oldCertificate.getPublicKey().getEncoded());
    assertThat(renewed.getNotAfter().toInstant()).isAfter(oldCertificate.getNotAfter().toInstant())
        .isBeforeOrEqualTo(issuer.certificate().getNotAfter().toInstant());
    assertThat(renewed.getNotAfter().toInstant()).isBetween(
        Instant.now().plus(44, ChronoUnit.DAYS), Instant.now().plus(46, ChronoUnit.DAYS));
    assertThat(renewed.getSubjectX500Principal()).isEqualTo(oldCertificate.getSubjectX500Principal());
    assertThat(renewed.getSubjectAlternativeNames().stream().map(name -> name.get(1).toString()).toList())
        .contains("urn:flowerca:user:" + admin.getId(), admin.getEmail()).doesNotContain("attacker.internal");
    assertThat(renewed.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.2");
    assertThat(certificates.findById(newId).orElseThrow().getProfile()).isEqualTo(CertificateProfile.ADMIN_CLIENT);
    assertThat(certificates.findAllByUserProfile_IdAndStatus(admin.getId(), CertificateStatus.ACTIVE))
        .extracting(CertificateEntity::getId).containsExactlyInAnyOrder(oldRecord.getId(), newId);
    assertThat(users.count()).isEqualTo(profilesBefore);
    assertThat(audit.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(AuditTargetType.CERTIFICATE, newId))
        .hasSize(2).anySatisfy(event -> {
          assertThat(event.getAction()).isEqualTo(AuditAction.ADMIN_CERTIFICATE_RENEWED);
          assertThat(event.getActorProfileId()).isEqualTo(admin.getId());
          assertThat(event.getActorCertificateId()).isEqualTo(oldRecord.getId());
          assertThat(event.getActorCertificateFingerprintSha256()).isEqualTo(oldRecord.getFingerprintSha256());
          assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
        });
    for (X509Certificate certificate : List.of(oldCertificate, renewed)) {
      mvc.perform(post("/api/v1/admin/users").requestAttr(
          ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE, new X509Certificate[] {certificate})
          .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(
              new CreateUserRequest("Created User", "new-" + UUID.randomUUID() + "@example.internal"))))
          .andExpect(status().isCreated());
    }
    assertThat(response).doesNotContain("PRIVATE KEY");
    assertThat(registration.isEnabled()).isFalse();
  }

  @Test
  void noCertificateCannotRenew() throws Exception {
    mvc.perform(post(ROUTE).contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void ordinaryUserCertificateCannotRenew() throws Exception {
    var user = users.saveAndFlush(new UserProfileEntity(
        "User", "ordinary-" + UUID.randomUUID() + "@example.internal", UserRole.USER));
    var userCertificate = issuance.issueUserClient(pki.createCsrPem("ignored.internal"), user)
        .issuedCertificate().certificate();
    mvc.perform(post(ROUTE).requestAttr(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] {userCertificate}).contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpect(status().isForbidden());
  }

  @Test
  void invalidAndOversizedCsrDoNotProduceRecords() throws Exception {
    long before = certificates.count();
    for (String csr : List.of("not-a-csr", "A".repeat(65537))) {
      request(json.writeValueAsString(new RenewAdminCertificateRequest(csr)))
          .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }
    assertThat(certificates.count()).isEqualTo(before);
  }

  @Test
  void renewalAuditFailureRollsBackCertificateAndBothSuccessEvents() throws Exception {
    long certificatesBefore = certificates.count();
    long auditBefore = audit.count();
    doThrow(new IllegalStateException("forced renewal audit failure")).when(audit)
        .save(argThat(event -> event.getAction() == AuditAction.ADMIN_CERTIFICATE_RENEWED));
    request(json.writeValueAsString(new RenewAdminCertificateRequest(pki.createCsrPem("ignored.internal"))))
        .andExpect(status().isInternalServerError()).andExpect(jsonPath("$.code").value("INTERNAL_ERROR"));
    assertThat(certificates.count()).isEqualTo(certificatesBefore);
    assertThat(audit.count()).isEqualTo(auditBefore);
    assertThat(certificates.findById(oldRecord.getId()).orElseThrow().getStatus()).isEqualTo(CertificateStatus.ACTIVE);
  }

  @Test
  void directServiceInvocationWithoutAuthenticationIsDenied() throws Exception {
    var command = new RenewAdminCertificateCommand(pki.createCsrPem("ignored.internal"));
    assertThatThrownBy(() -> renewal.renew(command, actor()))
        .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
  }

  @Test
  void databaseRoleChangeAfterAuthenticationIsRecheckedByUseCase() throws Exception {
    var actor = actor();
    SecurityContextHolder.getContext().setAuthentication(
        UsernamePasswordAuthenticationToken.authenticated(actor, null, List.of(new SimpleGrantedAuthority("ADMIN"))));
    jdbc.update("update user_profiles set role = 'USER' where email = ?", admin.getEmail());
    long before = certificates.count();
    var command = new RenewAdminCertificateCommand(pki.createCsrPem("ignored.internal"));
    assertThatThrownBy(() -> renewal.renew(command, actor)).isInstanceOf(AccessDeniedException.class);
    assertThat(certificates.count()).isEqualTo(before);
  }

  @Test
  void frameworkErrorsKeepStatusAndSafeBody() throws Exception {
    mvc.perform(get("/api/v1/public/does-not-exist"))
        .andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("NOT_FOUND"));
    mvc.perform(post("/api/v1/public/probe"))
        .andExpect(status().isMethodNotAllowed()).andExpect(header().string("Allow", "GET"))
        .andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"));
    mvc.perform(post(ROUTE).requestAttr(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] {oldCertificate}).contentType(MediaType.TEXT_PLAIN).content("invalid"))
        .andExpect(status().isUnsupportedMediaType()).andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
  }

  private ClientCertificatePrincipal actor() {
    return new ClientCertificatePrincipal(oldRecord.getId(), admin.getId(), oldRecord.getFingerprintSha256());
  }

  private org.springframework.test.web.servlet.ResultActions request(String body) throws Exception {
    return mvc.perform(post(ROUTE).requestAttr(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] {oldCertificate}).contentType(MediaType.APPLICATION_JSON).content(body));
  }
}
