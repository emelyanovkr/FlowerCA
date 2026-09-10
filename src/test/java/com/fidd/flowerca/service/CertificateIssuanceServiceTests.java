package com.fidd.flowerca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import org.junit.jupiter.api.Test;

class CertificateIssuanceServiceTests {

  @Test
  void parsesCsrAndPassesItToCertificateIssuer() {
    CsrParser parser = mock(CsrParser.class);
    CertificateIssuer issuer = mock(CertificateIssuer.class);
    IssuerIdentity issuerIdentity = mock(IssuerIdentity.class);
    IssuedCertificatePersistenceService persistence =
        mock(IssuedCertificatePersistenceService.class);
    ParsedCsr parsedCsr = mock(ParsedCsr.class);
    IssuedCertificate expected = mock(IssuedCertificate.class);
    when(parser.parse("pem-csr")).thenReturn(parsedCsr);
    when(issuer.issue(parsedCsr)).thenReturn(expected);

    IssuedCertificate actual =
        new CertificateIssuanceService(parser, issuer, issuerIdentity, persistence)
            .issue("pem-csr");

    assertThat(actual).isSameAs(expected);
    verify(parser).parse("pem-csr");
    verify(issuer).issue(parsedCsr);
    verify(persistence).persist(issuerIdentity, expected, CertificateProfile.TLS_SERVER);
  }
}
