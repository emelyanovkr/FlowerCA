package com.fidd.flowerca.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CaIssuerRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.time.Instant;
import java.util.Arrays;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(MySqlTestcontainerConfiguration.class)
@Transactional
class PersistenceRepositoriesTests {

  @Autowired private UserProfileRepository userProfiles;
  @Autowired private CaIssuerRepository issuers;
  @Autowired private CertificateRepository certificates;
  @Autowired private AuditEventRepository auditEvents;
  @Autowired private CertificateEntityFactory certificateEntityFactory;
  @Autowired private EntityManager entityManager;
  @Autowired private DataSource dataSource;

  @Test
  void usesMySqlConnectorAndFlywaySchema() throws Exception {
    try (Connection connection = dataSource.getConnection()) {
      assertThat(connection.getMetaData().getDatabaseProductName()).isEqualTo("MySQL");
      assertThat(connection.getMetaData().getDriverName()).contains("MySQL Connector/J");
    }

    Number migrationCount =
        (Number)
            entityManager
                .createNativeQuery("SELECT COUNT(*) FROM flyway_schema_history")
                .getSingleResult();
    assertThat(migrationCount.longValue()).isEqualTo(1L);
  }

  @Test
  void issuesCertificateAndPersistsAllCertificateFields() throws Exception {
    TestPki testPki = TestPki.create();
    CertificateIssuer certificateIssuer =
        new CertificateIssuer(testPki.issuerIdentity(), new InternalCertificatePolicy());
    CertificateIssuanceService issuanceService =
        new CertificateIssuanceService(new CsrParser(), certificateIssuer);

    IssuedCertificate issued =
        issuanceService.issue(
            testPki.createCsrPem("service-a.internal", "api.team.internal"));
    X509Certificate intermediate = testPki.intermediateCertificate();
    CaIssuerEntity issuer =
        issuers.save(
            new CaIssuerEntity(
                "flowerca-test-intermediate",
                intermediate.getSubjectX500Principal().getName(),
                unsigned(intermediate.getSerialNumber().toByteArray()),
                MessageDigest.getInstance("SHA-256")
                    .digest(intermediate.getPublicKey().getEncoded()),
                intermediate.getEncoded(),
                intermediate.getNotBefore().toInstant(),
                intermediate.getNotAfter().toInstant()));
    CertificateEntity saved =
        certificates.saveAndFlush(
            certificateEntityFactory.create(
                null, issuer, CertificateProfile.TLS_SERVER, issued.certificate()));
    byte[] expectedDer = issued.certificate().getEncoded();
    byte[] expectedFingerprint = MessageDigest.getInstance("SHA-256").digest(expectedDer);

    entityManager.clear();

    CertificateEntity loaded =
        certificates
            .findByIssuer_IdAndSerialNumber(issuer.getId(), saved.getSerialNumber())
            .orElseThrow();
    assertThat(loaded.getUserProfile()).isNull();
    assertThat(loaded.getProfile()).isEqualTo(CertificateProfile.TLS_SERVER);
    assertThat(loaded.getStatus()).isEqualTo(CertificateStatus.ACTIVE);
    assertThat(loaded.getSerialNumber())
        .isEqualTo(unsigned(issued.certificate().getSerialNumber().toByteArray()));
    assertThat(loaded.getFingerprintSha256()).isEqualTo(expectedFingerprint);
    assertThat(loaded.getSubjectDn())
        .isEqualTo(issued.certificate().getSubjectX500Principal().getName());
    assertThat(loaded.getCertificateDer()).isEqualTo(expectedDer);
    assertThat(loaded.getNotBefore()).isEqualTo(issued.certificate().getNotBefore().toInstant());
    assertThat(loaded.getNotAfter()).isEqualTo(issued.certificate().getNotAfter().toInstant());
    assertThat(loaded.getRevokedAt()).isNull();
    assertThat(loaded.getRevocationReason()).isNull();
    assertThat(loaded.getCreatedAt()).isNotNull();

    X509Certificate restored =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(loaded.getCertificateDer()));
    restored.verify(intermediate.getPublicKey());
    assertThat(restored.getPublicKey().getEncoded())
        .isEqualTo(testPki.clientKeyPair().getPublic().getEncoded());
  }

  @Test
  void persistsCertificateOwnershipAndAuditEvent() {
    Instant now = Instant.parse("2026-08-19T00:00:00Z");
    UserProfileEntity user =
        userProfiles.save(new UserProfileEntity("Alice", "alice@example.internal", UserRole.USER));
    CaIssuerEntity issuer =
        issuers.save(
            new CaIssuerEntity(
                "flowerca-intermediate",
                "CN=FlowerCA Intermediate CA",
                new byte[] {1},
                new byte[] {2},
                new byte[] {3},
                now.minusSeconds(60),
                now.plusSeconds(86400)));
    CertificateEntity certificate =
        certificates.save(
            new CertificateEntity(
                user,
                issuer,
                new byte[] {4},
                new byte[32],
                CertificateProfile.USER_CLIENT,
                "CN=Alice",
                new byte[] {5},
                now,
                now.plusSeconds(3600)));
    auditEvents.save(
        new AuditEventEntity(
            null,
            null,
            "CERTIFICATE_ISSUED",
            "CERTIFICATE",
            certificate.getId(),
            AuditResult.SUCCESS,
            "{\"profile\":\"USER_CLIENT\"}"));

    assertThat(userProfiles.findByEmailIgnoreCase("ALICE@EXAMPLE.INTERNAL")).contains(user);
    assertThat(issuers.findFirstByStatus(CaIssuerStatus.ACTIVE)).isPresent();
    assertThat(certificates.findByIssuer_IdAndSerialNumber(issuer.getId(), new byte[] {4}))
        .contains(certificate);
    assertThat(
            certificates.findAllByUserProfile_IdAndStatus(
                user.getId(), CertificateStatus.ACTIVE))
        .containsExactly(certificate);
    assertThat(
            auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
                "CERTIFICATE", certificate.getId()))
        .hasSize(1)
        .first()
        .extracting(AuditEventEntity::getAction)
        .isEqualTo("CERTIFICATE_ISSUED");
  }

  private byte[] unsigned(byte[] value) {
    if (value.length > 1 && value[0] == 0) {
      return Arrays.copyOfRange(value, 1, value.length);
    }
    return value;
  }
}
