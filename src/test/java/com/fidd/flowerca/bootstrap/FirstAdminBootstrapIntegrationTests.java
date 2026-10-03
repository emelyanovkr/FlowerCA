package com.fidd.flowerca.bootstrap;

import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.CurrentIssuerRegistry;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import com.fidd.flowerca.persistence.repository.AdminBootstrapStateRepository;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestIssuerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

@SpringBootTest(properties = "flowerca.issuer.enabled=false")
@Import({
  MySqlTestcontainerConfiguration.class,
  TestIssuerConfiguration.class,
  FirstAdminBootstrapIntegrationTests.BootstrapTestConfiguration.class
})
class FirstAdminBootstrapIntegrationTests {

  @Autowired private FirstAdminBootstrapService bootstrapService;
  @Autowired private AdminBootstrapStateRepository bootstrapStates;
  @Autowired private UserProfileRepository userProfiles;
  @Autowired private CertificateRepository certificates;
  @MockitoSpyBean private AuditEventRepository auditEvents;
  @Autowired private TestPki testPki;
  @Autowired private IssuerIdentity issuerIdentity;

  @Test
  void bootstrapsFirstAdminAtomicallyAndIsIdempotent(@TempDir Path tempDirectory)
      throws Exception {
    String csrPem = testPki.createCsrPem("spoofed-csr.internal");
    long usersBefore = userProfiles.count();
    long certificatesBefore = certificates.count();
    long auditBefore = auditEvents.count();

    try {
      doThrow(new IllegalStateException("forced bootstrap audit failure"))
          .when(auditEvents)
          .save(
              argThat(
                  event -> event.getAction() == AuditAction.ADMIN_BOOTSTRAPPED));

      assertThatThrownBy(
              () ->
                  bootstrapService.bootstrap(
                      "Alice Admin", "alice@example.internal", csrPem))
          .isInstanceOf(IllegalStateException.class)
          .hasMessage("forced bootstrap audit failure");
    } finally {
      reset(auditEvents);
    }

    assertThat(userProfiles.count()).isEqualTo(usersBefore);
    assertThat(certificates.count()).isEqualTo(certificatesBefore);
    assertThat(auditEvents.count()).isEqualTo(auditBefore);
    assertThat(bootstrapStates.findById(FirstAdminBootstrapService.STATE_NAME)).isEmpty();

    AdminBootstrapResult created =
        bootstrapService.bootstrap("Alice Admin", "alice@example.internal", csrPem);

    assertThat(created.created()).isTrue();
    UserProfileEntity admin = userProfiles.findById(created.userProfileId()).orElseThrow();
    assertThat(admin.getDisplayName()).isEqualTo("Alice Admin");
    assertThat(admin.getEmail()).isEqualTo("alice@example.internal");
    assertThat(admin.getRole()).isEqualTo(UserRole.ADMIN);
    assertThat(admin.getStatus()).isEqualTo(UserStatus.ACTIVE);

    CertificateEntity stored = certificates.findById(created.certificateId()).orElseThrow();
    assertThat(stored.getProfile()).isEqualTo(CertificateProfile.ADMIN_CLIENT);
    assertThat(stored.getStatus()).isEqualTo(CertificateStatus.ACTIVE);
    assertThat(certificates.findAllByUserProfile_IdAndStatus(admin.getId(), CertificateStatus.ACTIVE))
        .extracting(CertificateEntity::getId)
        .containsExactly(stored.getId());
    assertThat(stored.getCertificateDer())
        .isEqualTo(created.issuedCertificate().certificate().getEncoded());

    created.issuedCertificate().certificate().verify(issuerIdentity.certificate().getPublicKey());
    assertThat(created.issuedCertificate().certificate().getPublicKey().getEncoded())
        .isEqualTo(testPki.clientKeyPair().getPublic().getEncoded());
    assertThat(created.issuedCertificate().certificate().getExtendedKeyUsage())
        .containsExactly("1.3.6.1.5.5.7.3.2");
    assertThat(flattenSubjectAlternativeNames(
            created.issuedCertificate().certificate().getSubjectAlternativeNames()))
        .contains(
            "6:urn:flowerca:user:" + admin.getId(),
            "1:alice@example.internal")
        .doesNotContain("2:spoofed-csr.internal");

    assertThat(
            auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
                AuditTargetType.CERTIFICATE, stored.getId()))
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getAction()).isEqualTo(AuditAction.CERTIFICATE_ISSUED);
              assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
            });
    assertThat(
            auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
                AuditTargetType.USER_PROFILE, admin.getId()))
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getAction()).isEqualTo(AuditAction.ADMIN_BOOTSTRAPPED);
              assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
              assertThat(event.getActorProfileId()).isNull();
              assertThat(event.getActorCertificateId()).isNull();
              assertThat(event.getDetails()).isNull();
            });

    long usersAfterCreation = userProfiles.count();
    long certificatesAfterCreation = certificates.count();
    long auditsAfterCreation = auditEvents.count();
    AdminBootstrapResult existing =
        bootstrapService.bootstrap("Alice Admin", "ALICE@EXAMPLE.INTERNAL", csrPem);

    assertThat(existing.created()).isFalse();
    assertThat(existing.userProfileId()).isEqualTo(created.userProfileId());
    assertThat(existing.certificateId()).isEqualTo(created.certificateId());
    assertThat(userProfiles.count()).isEqualTo(usersAfterCreation);
    assertThat(certificates.count()).isEqualTo(certificatesAfterCreation);
    assertThat(auditEvents.count()).isEqualTo(auditsAfterCreation);

    assertThatThrownBy(
            () ->
                bootstrapService.bootstrap(
                    "Different Administrator", "alice@example.internal", csrPem))
        .isInstanceOf(AdminBootstrapException.class)
        .hasMessage("Configured administrator does not match the completed bootstrap");
    assertThat(userProfiles.count()).isEqualTo(usersAfterCreation);
    assertThat(certificates.count()).isEqualTo(certificatesAfterCreation);
    assertThat(auditEvents.count()).isEqualTo(auditsAfterCreation);

    Path csrPath = tempDirectory.resolve("first-admin.csr.pem");
    Path outputPath = tempDirectory.resolve("first-admin.chain.pem");
    Files.writeString(csrPath, csrPem, StandardCharsets.US_ASCII);
    AdminBootstrapProperties properties = new AdminBootstrapProperties();
    properties.setDisplayName("Alice Admin");
    properties.setEmail("alice@example.internal");
    properties.setCsrPath(csrPath);
    properties.setCertificateChainOutput(outputPath);
    FirstAdminBootstrapRunner runner =
        new FirstAdminBootstrapRunner(
            properties, bootstrapService, new CertificateChainPemEncoder());

    runner.run(null);
    byte[] firstOutput = Files.readAllBytes(outputPath);
    runner.run(null);
    assertThat(Files.readAllBytes(outputPath)).isEqualTo(firstOutput);
    assertThat(new String(firstOutput, StandardCharsets.US_ASCII))
        .contains("-----BEGIN CERTIFICATE-----")
        .doesNotContain("PRIVATE KEY");
    List<X509Certificate> exported =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(firstOutput))
            .stream()
            .map(certificate -> (X509Certificate) certificate)
            .toList();
    assertThat(exported).hasSize(created.issuedCertificate().fullChain().size());
    assertThat(exported.getFirst().getEncoded())
        .isEqualTo(created.issuedCertificate().certificate().getEncoded());
  }

  private List<String> flattenSubjectAlternativeNames(
      Collection<List<?>> subjectAlternativeNames) {
    return subjectAlternativeNames.stream()
        .map(name -> name.get(0) + ":" + name.get(1))
        .toList();
  }

  @TestConfiguration(proxyBeanMethods = false)
  static class BootstrapTestConfiguration {

    @Bean
    FirstAdminBootstrapService firstAdminBootstrapService(
        AdminBootstrapStateRepository bootstrapStates,
        UserProfileRepository userProfiles,
        CertificateRepository certificates,
        AuditEventRepository auditEvents,
        CurrentIssuerRegistry issuerRegistry,
        CertificateIssuanceService issuanceService,
        CsrParser csrParser,
        IssuerIdentity issuerIdentity) {
      return new FirstAdminBootstrapService(
          bootstrapStates,
          userProfiles,
          certificates,
          auditEvents,
          issuerRegistry,
          issuanceService,
          csrParser,
          issuerIdentity);
    }
  }
}
