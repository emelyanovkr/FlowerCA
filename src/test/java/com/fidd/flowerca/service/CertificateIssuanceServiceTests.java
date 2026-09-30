package com.fidd.flowerca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import org.junit.jupiter.api.Test;
import java.util.UUID;

class CertificateIssuanceServiceTests {

  @Test
  void parsesCsrAndPassesApprovedTlsIdentityToCertificateIssuer() {
    CsrParser parser = mock(CsrParser.class);
    CertificateIssuer issuer = mock(CertificateIssuer.class);
    IssuerIdentity issuerIdentity = mock(IssuerIdentity.class);
    IssuedCertificatePersistenceService persistence =
        mock(IssuedCertificatePersistenceService.class);
    ParsedCsr parsedCsr = mock(ParsedCsr.class);
    IssuedCertificate expected = mock(IssuedCertificate.class);
    CertificateIdentity.TlsServer identity =
        new CertificateIdentity.TlsServer(
            java.util.List.of("service-a.internal"));
    when(parser.parse("pem-csr")).thenReturn(parsedCsr);
    when(issuer.issue(parsedCsr, CertificateProfile.TLS_SERVER, identity))
        .thenReturn(expected);

    IssuedCertificate actual =
        new CertificateIssuanceService(parser, issuer, issuerIdentity, persistence)
            .issueTlsServer("pem-csr", identity);

    assertThat(actual).isSameAs(expected);
    verify(parser).parse("pem-csr");
    verify(issuer).issue(parsedCsr, CertificateProfile.TLS_SERVER, identity);
    verify(persistence).persist(issuerIdentity, expected, null);
  }

  @Test
  void buildsAdminIdentityFromPersistedOwnerAndPersistsOwnership() {
    CsrParser parser = mock(CsrParser.class);
    CertificateIssuer issuer = mock(CertificateIssuer.class);
    IssuerIdentity issuerIdentity = mock(IssuerIdentity.class);
    IssuedCertificatePersistenceService persistence =
        mock(IssuedCertificatePersistenceService.class);
    ParsedCsr parsedCsr = mock(ParsedCsr.class);
    IssuedCertificate issued = mock(IssuedCertificate.class);
    UserProfileEntity owner = mock(UserProfileEntity.class);
    CertificateEntity persisted = mock(CertificateEntity.class);
    UUID ownerId = UUID.randomUUID();
    UUID certificateId = UUID.randomUUID();
    CertificateIdentity.User approvedIdentity =
        new CertificateIdentity.User(ownerId, "Alice Admin", "alice@example.internal");
    when(owner.getId()).thenReturn(ownerId);
    when(owner.getDisplayName()).thenReturn("Alice Admin");
    when(owner.getEmail()).thenReturn("alice@example.internal");
    when(parser.parse("admin-csr")).thenReturn(parsedCsr);
    when(issuer.issue(parsedCsr, CertificateProfile.ADMIN_CLIENT, approvedIdentity))
        .thenReturn(issued);
    when(persistence.persist(issuerIdentity, issued, owner)).thenReturn(persisted);
    when(persisted.getId()).thenReturn(certificateId);

    PersistedCertificateIssuance result =
        new CertificateIssuanceService(parser, issuer, issuerIdentity, persistence)
            .issueAdminClient("admin-csr", owner);

    assertThat(result.issuedCertificate()).isSameAs(issued);
    assertThat(result.certificateId()).isEqualTo(certificateId);
    verify(issuer).issue(parsedCsr, CertificateProfile.ADMIN_CLIENT, approvedIdentity);
    verify(persistence).persist(issuerIdentity, issued, owner);
  }
}
