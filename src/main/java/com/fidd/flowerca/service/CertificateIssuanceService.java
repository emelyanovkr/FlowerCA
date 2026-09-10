package com.fidd.flowerca.service;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.persistence.model.CertificateProfile;
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
  private final IssuerIdentity issuerIdentity;
  private final IssuedCertificatePersistenceService persistenceService;

  public CertificateIssuanceService(
      CsrParser csrParser,
      CertificateIssuer certificateIssuer,
      IssuerIdentity issuerIdentity,
      IssuedCertificatePersistenceService persistenceService) {
    this.csrParser = csrParser;
    this.certificateIssuer = certificateIssuer;
    this.issuerIdentity = issuerIdentity;
    this.persistenceService = persistenceService;
  }

  public IssuedCertificate issue(String csrPem) {
    ParsedCsr parsedCsr = csrParser.parse(csrPem);
    IssuedCertificate issuedCertificate = certificateIssuer.issue(parsedCsr);
    persistenceService.persist(issuerIdentity, issuedCertificate, CertificateProfile.TLS_SERVER);
    return issuedCertificate;
  }
}
