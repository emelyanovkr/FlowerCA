package com.fidd.flowerca.application;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(
    prefix = "flowerca.issuer",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class CertificateIssuanceService {

  private final CsrParser csrParser;
  private final CertificateIssuer certificateIssuer;

  public CertificateIssuanceService(
      CsrParser csrParser, CertificateIssuer certificateIssuer) {
    this.csrParser = csrParser;
    this.certificateIssuer = certificateIssuer;
  }

  public IssuedCertificate issue(String csrPem) {
    ParsedCsr parsedCsr = csrParser.parse(csrPem);
    return certificateIssuer.issue(parsedCsr);
  }
}
