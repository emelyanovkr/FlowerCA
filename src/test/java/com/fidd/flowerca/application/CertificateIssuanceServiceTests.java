package com.fidd.flowerca.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import org.junit.jupiter.api.Test;

class CertificateIssuanceServiceTests {

  @Test
  void parsesCsrAndPassesItToCertificateIssuer() {
    CsrParser parser = mock(CsrParser.class);
    CertificateIssuer issuer = mock(CertificateIssuer.class);
    ParsedCsr parsedCsr = mock(ParsedCsr.class);
    IssuedCertificate expected = mock(IssuedCertificate.class);
    when(parser.parse("pem-csr")).thenReturn(parsedCsr);
    when(issuer.issue(parsedCsr)).thenReturn(expected);

    IssuedCertificate actual =
        new CertificateIssuanceService(parser, issuer).issue("pem-csr");

    assertThat(actual).isSameAs(expected);
    verify(parser).parse("pem-csr");
    verify(issuer).issue(parsedCsr);
  }
}
