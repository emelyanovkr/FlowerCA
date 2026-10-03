package com.fidd.flowerca.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

class ClientCertificateAuthenticationServiceTests {

  private static final Instant NOW = Instant.parse("2026-09-16T00:00:00Z");

  @Test
  void authenticatesActiveAdminByFingerprintIssuerAndSerial() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);

    Optional<ClientCertificateAuthentication> result = fixture.service.authenticate(fixture.presented);

    assertThat(result).isPresent();
    assertThat(result.orElseThrow().administrator()).isTrue();
    assertThat(result.orElseThrow().principal().certificateId()).isEqualTo(fixture.certificateId);
    assertThat(result.orElseThrow().principal().profileId()).isEqualTo(fixture.profileId);
  }

  @Test
  void recognizesActiveUserCertificateOwnedByAdminWithoutAdminAuthority() throws Exception {
    Fixture fixture = fixture(CertificateProfile.USER_CLIENT, UserRole.ADMIN);

    Optional<ClientCertificateAuthentication> result = fixture.service.authenticate(fixture.presented);

    assertThat(result).isPresent();
    assertThat(result.orElseThrow().administrator()).isFalse();
  }

  @Test
  void rejectsExpiredCertificateEvenWhenDatabaseStatusIsActive() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getNotAfter()).thenReturn(NOW);

    assertThat(fixture.service.authenticate(fixture.presented)).isEmpty();
  }

  @Test
  void rejectsRevokedCertificate() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getStatus()).thenReturn(CertificateStatus.REVOKED);

    assertThat(fixture.service.authenticate(fixture.presented)).isEmpty();
  }

  @Test
  void blockedOwnerDoesNotReceiveAdminAuthority() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getUserProfile().getStatus()).thenReturn(UserStatus.BLOCKED);

    Optional<ClientCertificateAuthentication> result = fixture.service.authenticate(fixture.presented);

    assertThat(result).isPresent();
    assertThat(result.orElseThrow().administrator()).isFalse();
  }

  @Test
  void rejectsIssuerOrSerialMismatch() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getSerialNumber()).thenReturn(new byte[] {0x7f});

    assertThat(fixture.service.authenticate(fixture.presented)).isEmpty();
  }

  private Fixture fixture(CertificateProfile profile, UserRole role) throws Exception {
    CertificateRepository repository = mock(CertificateRepository.class);
    X509Certificate presented = mock(X509Certificate.class);
    CertificateEntity stored = mock(CertificateEntity.class);
    CaIssuerEntity issuer = mock(CaIssuerEntity.class);
    UserProfileEntity owner = mock(UserProfileEntity.class);
    byte[] encoded = new byte[] {1, 2, 3, 4};
    byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(encoded);
    UUID certificateId = UUID.randomUUID();
    UUID profileId = UUID.randomUUID();
    X500Principal issuerPrincipal = new X500Principal("CN=FlowerCA Intermediate CA");
    when(presented.getEncoded()).thenReturn(encoded);
    when(presented.getSerialNumber()).thenReturn(BigInteger.valueOf(42));
    when(presented.getIssuerX500Principal()).thenReturn(issuerPrincipal);
    when(repository.findWithUserProfileAndIssuerByFingerprintSha256(fingerprint))
        .thenReturn(Optional.of(stored));
    when(stored.getId()).thenReturn(certificateId);
    when(stored.getSerialNumber()).thenReturn(new byte[] {42});
    when(stored.getIssuer()).thenReturn(issuer);
    when(stored.getUserProfile()).thenReturn(owner);
    when(stored.getProfile()).thenReturn(profile);
    when(stored.getStatus()).thenReturn(CertificateStatus.ACTIVE);
    when(stored.getNotBefore()).thenReturn(NOW.minusSeconds(60));
    when(stored.getNotAfter()).thenReturn(NOW.plusSeconds(60));
    when(issuer.getSubjectDn()).thenReturn(issuerPrincipal.getName());
    when(issuer.getStatus()).thenReturn(CaIssuerStatus.ACTIVE);
    when(owner.getId()).thenReturn(profileId);
    when(owner.getRole()).thenReturn(role);
    when(owner.getStatus()).thenReturn(UserStatus.ACTIVE);
    ClientCertificateAuthenticationService service =
        new ClientCertificateAuthenticationService(
            repository, Clock.fixed(NOW, ZoneOffset.UTC));
    return new Fixture(service, presented, stored, certificateId, profileId);
  }

  @Test
  void adminCertificateOwnedByOrdinaryUserDoesNotGrantAdminAuthority() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.USER);
    assertThat(fixture.service.authenticate(fixture.presented).orElseThrow().administrator()).isFalse();
  }

  @Test
  void rejectsCertificateBeforeNotBefore() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getNotBefore()).thenReturn(NOW.plusSeconds(1));
    assertThat(fixture.service.authenticate(fixture.presented)).isEmpty();
  }

  @Test
  void retiredIssuerCannotAuthenticate() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getIssuer().getStatus()).thenReturn(CaIssuerStatus.RETIRED);
    assertThat(fixture.service.authenticate(fixture.presented)).isEmpty();
  }

  @Test
  void missingOwnerDoesNotGrantAdminAuthority() throws Exception {
    Fixture fixture = fixture(CertificateProfile.ADMIN_CLIENT, UserRole.ADMIN);
    when(fixture.stored.getUserProfile()).thenReturn(null);
    assertThat(fixture.service.authenticate(fixture.presented).orElseThrow().administrator()).isFalse();
  }

  private record Fixture(
      ClientCertificateAuthenticationService service,
      X509Certificate presented,
      CertificateEntity stored,
      UUID certificateId,
      UUID profileId) {}
}
