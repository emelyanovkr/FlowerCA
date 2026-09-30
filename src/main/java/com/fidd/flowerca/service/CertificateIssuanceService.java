package com.fidd.flowerca.service;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
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

  public IssuedCertificate issueTlsServer(
      String csrPem, CertificateIdentity.TlsServer identity) {
    ParsedCsr parsedCsr = csrParser.parse(csrPem);
    IssuedCertificate issuedCertificate =
        certificateIssuer.issue(parsedCsr, CertificateProfile.TLS_SERVER, identity);
    persistenceService.persist(issuerIdentity, issuedCertificate, null);
    return issuedCertificate;
  }

  public PersistedCertificateIssuance issueAdminClient(
      String csrPem, UserProfileEntity owner) {
    return issueClient(csrPem, owner, CertificateProfile.ADMIN_CLIENT);
  }

  public PersistedCertificateIssuance issueUserClient(
      String csrPem, UserProfileEntity owner) {
    return issueClient(csrPem, owner, CertificateProfile.USER_CLIENT);
  }

  private PersistedCertificateIssuance issueClient(
      String csrPem, UserProfileEntity owner, CertificateProfile profile) {
    CertificateIdentity.User identity =
        new CertificateIdentity.User(
            owner.getId(), owner.getDisplayName(), owner.getEmail());
    ParsedCsr parsedCsr = csrParser.parse(csrPem);
    IssuedCertificate issuedCertificate =
        certificateIssuer.issue(parsedCsr, profile, identity);
    CertificateEntity certificate =
        persistenceService.persist(issuerIdentity, issuedCertificate, owner);
    return new PersistedCertificateIssuance(issuedCertificate, certificate.getId());
  }
}
