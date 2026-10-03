package com.fidd.flowerca.bootstrap;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.persistence.CurrentIssuerRegistry;
import com.fidd.flowerca.persistence.entity.*;
import com.fidd.flowerca.persistence.model.*;
import com.fidd.flowerca.persistence.repository.*;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.testsupport.TestPki;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class FirstAdminBootstrapValidityTests {

  private static TestPki pki;
  private static String csr;
  private static java.security.cert.X509Certificate certificate;
  private static final UUID OWNER = UUID.randomUUID();

  @BeforeAll
  static void material() throws Exception {
    pki = TestPki.create();
    csr = pki.createCsrPem("ignored.internal");
    certificate = new CertificateIssuer(pki.issuerIdentity(), new InternalCertificatePolicy())
        .issue(new CsrParser().parse(csr), CertificateProfile.ADMIN_CLIENT,
            new CertificateIdentity.User(OWNER, "Admin", "admin@example.internal")).certificate();
  }

  @Test
  void validRetryExportsSameCertificateWithoutIssuing() throws Exception {
    var fixture = fixture(certificate.getNotBefore().toInstant().plusSeconds(1), false);
    var result = fixture.service().bootstrap("Admin", "admin@example.internal", csr);
    assertThat(result.created()).isFalse();
    assertThat(result.issuedCertificate().certificate().getEncoded()).isEqualTo(certificate.getEncoded());
    verifyNoInteractions(fixture.issuance());
  }

  @Test
  void expiryBoundaryDoesNotReportBootstrapSuccess() throws Exception {
    var fixture = fixture(certificate.getNotAfter().toInstant(), false);
    assertThatThrownBy(() -> fixture.service().bootstrap("Admin", "admin@example.internal", csr))
        .isInstanceOf(AdminBootstrapException.class).hasMessageContaining("not currently valid");
    verifyNoInteractions(fixture.issuance());
  }

  @Test
  void futureCertificateDoesNotReportBootstrapSuccess() throws Exception {
    var fixture = fixture(certificate.getNotBefore().toInstant().minusSeconds(1), false);
    assertThatThrownBy(() -> fixture.service().bootstrap("Admin", "admin@example.internal", csr))
        .isInstanceOf(AdminBootstrapException.class).hasMessageContaining("not currently valid");
    verifyNoInteractions(fixture.issuance());
  }

  @Test
  void checksActualDerValidityEvenWhenStoredDatesClaimItIsValid() throws Exception {
    var fixture = fixture(certificate.getNotAfter().toInstant().plusSeconds(1), true);
    assertThatThrownBy(() -> fixture.service().bootstrap("Admin", "admin@example.internal", csr))
        .isInstanceOf(AdminBootstrapException.class).hasMessageContaining("not currently valid");
    verifyNoInteractions(fixture.issuance());
  }

  @Test
  void anotherPublicKeyCannotReplaceCompletedBootstrap() throws Exception {
    var fixture = fixture(Instant.now(), false);
    String differentCsr = TestPki.create().createCsrPem("ignored.internal");
    assertThatThrownBy(() -> fixture.service().bootstrap("Admin", "admin@example.internal", differentCsr))
        .isInstanceOf(AdminBootstrapException.class).hasMessageContaining("CSR does not match");
    verifyNoInteractions(fixture.issuance());
  }

  private Fixture fixture(Instant now, boolean dishonestDates) throws Exception {
    var owner = mock(UserProfileEntity.class);
    when(owner.getId()).thenReturn(OWNER);
    when(owner.getRole()).thenReturn(UserRole.ADMIN);
    when(owner.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(owner.getDisplayName()).thenReturn("Admin");
    when(owner.getEmail()).thenReturn("admin@example.internal");
    var stored = mock(CertificateEntity.class);
    when(stored.getId()).thenReturn(UUID.randomUUID());
    when(stored.getUserProfile()).thenReturn(owner);
    when(stored.getProfile()).thenReturn(CertificateProfile.ADMIN_CLIENT);
    when(stored.getStatus()).thenReturn(CertificateStatus.ACTIVE);
    when(stored.getCertificateDer()).thenReturn(certificate.getEncoded());
    when(stored.getNotBefore()).thenReturn(dishonestDates ? now.minusSeconds(60) : certificate.getNotBefore().toInstant());
    when(stored.getNotAfter()).thenReturn(dishonestDates ? now.plusSeconds(60) : certificate.getNotAfter().toInstant());
    var state = mock(AdminBootstrapStateEntity.class);
    when(state.getUserProfile()).thenReturn(owner);
    when(state.getCertificate()).thenReturn(stored);
    when(state.getCompletedAt()).thenReturn(certificate.getNotBefore().toInstant());
    var states = mock(AdminBootstrapStateRepository.class);
    when(states.findById(FirstAdminBootstrapService.STATE_NAME)).thenReturn(Optional.of(state));
    var issuance = mock(CertificateIssuanceService.class);
    var service = new FirstAdminBootstrapService(states, mock(UserProfileRepository.class),
        mock(CertificateRepository.class), mock(AuditEventRepository.class),
        mock(CurrentIssuerRegistry.class), issuance, new CsrParser(), pki.issuerIdentity(), Clock.fixed(now, ZoneOffset.UTC));
    return new Fixture(service, issuance);
  }

  private record Fixture(FirstAdminBootstrapService service, CertificateIssuanceService issuance) {}
}
