package com.fidd.flowerca.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CaIssuerRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestIssuerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

@SpringBootTest
@Import({MySqlTestcontainerConfiguration.class, TestIssuerConfiguration.class})
class PersistenceRepositoriesTests {

  @Autowired private UserProfileRepository userProfiles;
  @Autowired private CaIssuerRepository issuers;
  @Autowired private CertificateRepository certificates;
  @MockitoSpyBean private AuditEventRepository auditEvents;
  @Autowired private CertificateIssuanceService issuanceService;
  @Autowired private IssuedCertificatePersistenceService persistenceService;
  @Autowired private IssuerIdentity issuerIdentity;
  @Autowired private TestPki testPki;
  @Autowired private EntityManager entityManager;

  @Test
  void issuesCertificateAndPersistsAllCertificateFields() throws Exception {
    IssuedCertificate issued =
        issuanceService.issue(
            testPki.createCsrPem("service-a.internal", "api.team.internal"));
    CaIssuerEntity issuer = currentIssuer();
    byte[] serialNumber = unsigned(issued.certificate().getSerialNumber().toByteArray());
    byte[] expectedDer = issued.certificate().getEncoded();
    byte[] expectedFingerprint = MessageDigest.getInstance("SHA-256").digest(expectedDer);

    entityManager.clear();

    CertificateEntity loaded =
        certificates
            .findByIssuer_IdAndSerialNumber(issuer.getId(), serialNumber)
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
    assertThat(auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
            AuditTargetType.CERTIFICATE, loaded.getId()))
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getAction()).isEqualTo(AuditAction.CERTIFICATE_ISSUED);
              assertThat(event.getResult()).isEqualTo(AuditResult.SUCCESS);
              assertThat(event.getDetails()).contains("\"profile\"", "\"TLS_SERVER\"");
            });
  }

  @Test
  void restoresPersistedCertificateFromDer() throws Exception {
    IssuedCertificate issued =
        issuanceService.issue(testPki.createCsrPem("der-round-trip.internal"));
    CaIssuerEntity issuer = currentIssuer();
    byte[] serialNumber = unsigned(issued.certificate().getSerialNumber().toByteArray());

    entityManager.clear();

    CertificateEntity loaded =
        certificates
            .findByIssuer_IdAndSerialNumber(issuer.getId(), serialNumber)
            .orElseThrow();
    X509Certificate restored =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(loaded.getCertificateDer()));
    restored.verify(issuerIdentity.certificate().getPublicKey());
    assertThat(restored.getEncoded()).isEqualTo(issued.certificate().getEncoded());
    assertThat(restored.getPublicKey().getEncoded())
        .isEqualTo(testPki.clientKeyPair().getPublic().getEncoded());
  }

  @Test
  void usesRegisteredIssuerForMultipleCertificates() throws Exception {
    CaIssuerEntity issuer = currentIssuer();
    IssuedCertificate first =
        issuanceService.issue(testPki.createCsrPem("issuer-one.internal"));
    IssuedCertificate second =
        issuanceService.issue(testPki.createCsrPem("issuer-two.internal"));

    entityManager.clear();

    assertThat(
            certificates.findByIssuer_IdAndSerialNumber(
                issuer.getId(), unsigned(first.certificate().getSerialNumber().toByteArray())))
        .isPresent();
    assertThat(
            certificates.findByIssuer_IdAndSerialNumber(
                issuer.getId(), unsigned(second.certificate().getSerialNumber().toByteArray())))
        .isPresent();
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
                new byte[32],
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
            AuditAction.CERTIFICATE_ISSUED,
            AuditTargetType.CERTIFICATE,
            certificate.getId(),
            AuditResult.SUCCESS,
            "{\"profile\":\"USER_CLIENT\"}"));

    assertThat(userProfiles.findByEmailIgnoreCase("ALICE@EXAMPLE.INTERNAL"))
        .get()
        .extracting(UserProfileEntity::getId)
        .isEqualTo(user.getId());
    assertThat(issuers.findByFingerprintSha256(new byte[32]))
        .get()
        .extracting(CaIssuerEntity::getId)
        .isEqualTo(issuer.getId());
    assertThat(certificates.findByIssuer_IdAndSerialNumber(issuer.getId(), new byte[] {4}))
        .get()
        .extracting(CertificateEntity::getId)
        .isEqualTo(certificate.getId());
    assertThat(
            certificates.findAllByUserProfile_IdAndStatus(
                user.getId(), CertificateStatus.ACTIVE))
        .extracting(CertificateEntity::getId)
        .containsExactly(certificate.getId());
    assertThat(
            auditEvents.findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
                AuditTargetType.CERTIFICATE, certificate.getId()))
        .hasSize(1)
        .first()
        .extracting(AuditEventEntity::getAction)
        .isEqualTo(AuditAction.CERTIFICATE_ISSUED);
  }

  @Test
  void rollsBackCertificateWhenAuditInsertFails() {
    long certificateCountBefore = certificates.count();
    long auditCountBefore = auditEvents.count();
    try {
      doThrow(new IllegalStateException("forced audit failure"))
          .when(auditEvents)
          .save(any(AuditEventEntity.class));
      IssuedCertificate issuedCertificate =
          issuedCertificate(new byte[] {0x31}, uniqueDer("audit-rollback"));

      assertThatThrownBy(
              () ->
                  persistenceService.persist(
                      issuerIdentity, issuedCertificate, CertificateProfile.TLS_SERVER))
          .isInstanceOf(IllegalStateException.class)
          .hasMessage("forced audit failure");
    } finally {
      reset(auditEvents);
    }

    entityManager.clear();
    assertThat(certificates.count()).isEqualTo(certificateCountBefore);
    assertThat(auditEvents.count()).isEqualTo(auditCountBefore);
  }

  @Test
  void duplicateIssuerSerialRollsBackWithoutAuditEvent() {
    byte[] serialNumber = new byte[] {0x32};
    persistenceService.persist(
        issuerIdentity,
        issuedCertificate(serialNumber, uniqueDer("serial-original")),
        CertificateProfile.TLS_SERVER);
    long certificateCountBeforeConflict = certificates.count();
    long auditCountBeforeConflict = auditEvents.count();

    assertThatThrownBy(
            () ->
                persistenceService.persist(
                    issuerIdentity,
                    issuedCertificate(serialNumber, uniqueDer("serial-conflict")),
                    CertificateProfile.TLS_SERVER))
        .isInstanceOf(DataIntegrityViolationException.class);

    entityManager.clear();
    assertThat(certificates.count()).isEqualTo(certificateCountBeforeConflict);
    assertThat(auditEvents.count()).isEqualTo(auditCountBeforeConflict);
  }

  @Test
  void duplicateFingerprintRollsBackWithoutAuditEvent() {
    byte[] certificateDer = uniqueDer("fingerprint-conflict");
    persistenceService.persist(
        issuerIdentity,
        issuedCertificate(new byte[] {0x33}, certificateDer),
        CertificateProfile.TLS_SERVER);
    long certificateCountBeforeConflict = certificates.count();
    long auditCountBeforeConflict = auditEvents.count();

    assertThatThrownBy(
            () ->
                persistenceService.persist(
                    issuerIdentity,
                    issuedCertificate(new byte[] {0x34}, certificateDer),
                    CertificateProfile.TLS_SERVER))
        .isInstanceOf(DataIntegrityViolationException.class);

    entityManager.clear();
    assertThat(certificates.count()).isEqualTo(certificateCountBeforeConflict);
    assertThat(auditEvents.count()).isEqualTo(auditCountBeforeConflict);
  }

  private IssuedCertificate issuedCertificate(byte[] serialNumber, byte[] certificateDer) {
    X509Certificate certificate = mock(X509Certificate.class);
    try {
      when(certificate.getEncoded()).thenReturn(certificateDer);
    } catch (Exception exception) {
      throw new AssertionError(exception);
    }
    when(certificate.getSerialNumber()).thenReturn(new BigInteger(1, serialNumber));
    when(certificate.getSubjectX500Principal())
        .thenReturn(new X500Principal("CN=Persistence Transaction Test"));
    when(certificate.getNotBefore()).thenReturn(Date.from(Instant.parse("2026-01-01T00:00:00Z")));
    when(certificate.getNotAfter()).thenReturn(Date.from(Instant.parse("2027-01-01T00:00:00Z")));
    return new IssuedCertificate(certificate, List.of(issuerIdentity.certificate()));
  }

  private byte[] uniqueDer(String label) {
    return (label + "-" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8);
  }

  private CaIssuerEntity currentIssuer() throws Exception {
    byte[] fingerprint =
        MessageDigest.getInstance("SHA-256").digest(issuerIdentity.certificate().getEncoded());
    return issuers.findByFingerprintSha256(fingerprint).orElseThrow();
  }

  private byte[] unsigned(byte[] value) {
    if (value.length > 1 && value[0] == 0) {
      return Arrays.copyOfRange(value, 1, value.length);
    }
    return value;
  }
}
