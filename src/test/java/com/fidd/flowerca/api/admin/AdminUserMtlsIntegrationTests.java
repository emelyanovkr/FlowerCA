package com.fidd.flowerca.api.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
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
import com.fidd.flowerca.security.ClientCertificateAuthenticationFilter;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestIssuerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "flowerca.issuer.enabled=false")
@AutoConfigureMockMvc
@Import({MySqlTestcontainerConfiguration.class, TestIssuerConfiguration.class})
class AdminUserMtlsIntegrationTests {

  private static final String ADMIN_EMAIL = "mtls-admin@example.internal";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserProfileRepository users;
  @Autowired private CertificateRepository certificates;
  @Autowired private AuditEventRepository auditEvents;
  @Autowired private CertificateIssuanceService issuanceService;
  @Autowired private CertificateIssuer certificateIssuer;
  @Autowired private CsrParser csrParser;
  @Autowired private TestPki testPki;

  private UserProfileEntity admin;
  private CertificateEntity adminCertificateRecord;
  private X509Certificate adminCertificate;

  @BeforeEach
  void prepareAdministrator() throws Exception {
    admin =
        users.findByEmailIgnoreCase(ADMIN_EMAIL)
            .orElseGet(
                () ->
                    users.saveAndFlush(
                        new UserProfileEntity("mTLS Admin", ADMIN_EMAIL, UserRole.ADMIN)));
    List<CertificateEntity> activeCertificates =
        certificates.findAllByUserProfile_IdAndStatus(admin.getId(), CertificateStatus.ACTIVE);
    adminCertificateRecord =
        activeCertificates.stream()
            .filter(certificate -> certificate.getProfile() == CertificateProfile.ADMIN_CLIENT)
            .findFirst()
            .orElseGet(
                () -> {
                  try {
                    UUID certificateId =
                        issuanceService
                            .issueAdminClient(
                                testPki.createCsrPem("ignored-admin-csr.internal"), admin)
                            .certificateId();
                    return certificates.findById(certificateId).orElseThrow();
                  } catch (Exception exception) {
                    throw new IllegalStateException(exception);
                  }
                });
    adminCertificate = decode(adminCertificateRecord.getCertificateDer());
  }

  @Test
  void publicProbeDoesNotRequireClientCertificate() throws Exception {
    mockMvc.perform(get("/api/v1/public/probe"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("ok"));
  }

  @Test
  void adminEndpointWithoutCertificateReturnsConstant401() throws Exception {
    mockMvc.perform(
            post("/api/v1/admin/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"No Cert\",\"email\":\"no-cert@example.internal\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
        .andExpect(jsonPath("$.message").value("Authentication required"));
  }

  @Test
  void trustedButUnknownCertificateReturns401() throws Exception {
    X509Certificate unknown =
        certificateIssuer
            .issue(
                csrParser.parse(testPki.createCsrPem("ignored-unknown.internal")),
                CertificateProfile.ADMIN_CLIENT,
                new CertificateIdentity.User(
                    UUID.randomUUID(), "Unknown Admin", "unknown@example.internal"))
            .certificate();

    mockMvc.perform(
            post("/api/v1/admin/users")
                .requestAttr(
                    ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
                    new X509Certificate[] {unknown})
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"Unknown\",\"email\":\"unknown-user@example.internal\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
  }

  @Test
  void activeUserCertificateIsAuthenticatedButForbidden() throws Exception {
    UserProfileEntity user =
        users.saveAndFlush(
            new UserProfileEntity(
                "Ordinary User",
                "ordinary-" + UUID.randomUUID() + "@example.internal",
                UserRole.USER));
    UUID certificateId =
        issuanceService
            .issueUserClient(testPki.createCsrPem("ignored-user.internal"), user)
            .certificateId();
    X509Certificate userCertificate =
        decode(certificates.findById(certificateId).orElseThrow().getCertificateDer());

    mockMvc.perform(
            post("/api/v1/admin/users")
                .requestAttr(
                    ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
                    new X509Certificate[] {userCertificate})
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"Forbidden\",\"email\":\"forbidden@example.internal\"}"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("FORBIDDEN"));
  }

  @Test
  void activeAdminCertificateCreatesUserAndAuditsFingerprint() throws Exception {
    String email = "created-" + UUID.randomUUID() + "@example.internal";

    mockMvc.perform(
            post("/api/v1/admin/users")
                .requestAttr(
                    ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
                    new X509Certificate[] {adminCertificate})
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"displayName\":\"  Created User  \",\"email\":\""
                        + email.toUpperCase()
                        + "\"}"))
        .andExpect(status().isCreated())
        .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith("/api/v1/admin/users/")))
        .andExpect(jsonPath("$.displayName").value("Created User"))
        .andExpect(jsonPath("$.email").value(email))
        .andExpect(jsonPath("$.role").value("USER"))
        .andExpect(jsonPath("$.status").value("ACTIVE"));

    UserProfileEntity created = users.findByEmailIgnoreCase(email).orElseThrow();
    List<AuditEventEntity> events =
        auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
            AuditTargetType.USER_PROFILE, created.getId());
    assertThat(events).singleElement().satisfies(
        event -> {
          assertThat(event.getAction()).isEqualTo(AuditAction.USER_CREATED);
          assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
          assertThat(event.getActorProfileId()).isEqualTo(admin.getId());
          assertThat(event.getActorCertificateId()).isEqualTo(adminCertificateRecord.getId());
          try {
            assertThat(event.getActorCertificateFingerprintSha256())
                .isEqualTo(
                    MessageDigest.getInstance("SHA-256").digest(adminCertificate.getEncoded()));
          } catch (Exception exception) {
            throw new AssertionError(exception);
          }
        });
  }

  @Test
  void malformedAdminRequestReturnsConstant400() throws Exception {
    mockMvc.perform(
            post("/api/v1/admin/users")
                .requestAttr(
                    ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
                    new X509Certificate[] {adminCertificate})
                .contentType(MediaType.APPLICATION_JSON)
                .content("{not-json}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
        .andExpect(jsonPath("$.message").value("Request is invalid"));
  }

  private X509Certificate decode(byte[] certificateDer) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certificateDer));
  }
}
