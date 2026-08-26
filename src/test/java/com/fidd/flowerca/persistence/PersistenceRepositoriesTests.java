package com.fidd.flowerca.persistence;

import static org.assertj.core.api.Assertions.assertThat;

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
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class PersistenceRepositoriesTests {

  @Autowired private UserProfileRepository userProfiles;
  @Autowired private CaIssuerRepository issuers;
  @Autowired private CertificateRepository certificates;
  @Autowired private AuditEventRepository auditEvents;

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
    assertThat(issuers.findFirstByStatus(CaIssuerStatus.ACTIVE)).contains(issuer);
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
}
