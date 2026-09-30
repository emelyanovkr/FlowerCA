package com.fidd.flowerca.persistence;

import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IssuedCertificatePersistenceService {

  private final CurrentIssuerRegistry issuerRegistry;
  private final CertificateEntityFactory certificateFactory;
  private final CertificateRepository certificates;
  private final AuditEventRepository auditEvents;

  public IssuedCertificatePersistenceService(
      CurrentIssuerRegistry issuerRegistry,
      CertificateEntityFactory certificateFactory,
      CertificateRepository certificates,
      AuditEventRepository auditEvents) {
    this.issuerRegistry = issuerRegistry;
    this.certificateFactory = certificateFactory;
    this.certificates = certificates;
    this.auditEvents = auditEvents;
  }

  @Transactional
  public CertificateEntity persist(
      IssuerIdentity issuerIdentity,
      IssuedCertificate issuedCertificate,
      UserProfileEntity owner) {
    validateOwnership(issuedCertificate, owner);
    CaIssuerEntity issuer = issuerRegistry.requireRegistered(issuerIdentity);
    CertificateEntity certificate =
        certificates.save(
            certificateFactory.create(
                owner, issuer, issuedCertificate.profile(), issuedCertificate.certificate()));
    auditEvents.save(
        new AuditEventEntity(
            null,
            null,
            null,
            AuditAction.CERTIFICATE_ISSUED,
            AuditTargetType.CERTIFICATE,
            certificate.getId(),
            AuditResult.SUCCESS,
            "{\"profile\":\"" + issuedCertificate.profile().name() + "\"}"));
    return certificate;
  }

  private void validateOwnership(
      IssuedCertificate issuedCertificate, UserProfileEntity owner) {
    switch (issuedCertificate.profile()) {
      case TLS_SERVER -> {
        if (owner != null) {
          throw new CertificatePersistenceException(
              "TLS server certificates cannot have a user owner");
        }
      }
      case USER_CLIENT, ADMIN_CLIENT -> {
        if (owner == null) {
          throw new CertificatePersistenceException(
              "Client certificates require a user owner");
        }
      }
    }
  }
}
