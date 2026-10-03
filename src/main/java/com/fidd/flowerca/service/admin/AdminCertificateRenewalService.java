package com.fidd.flowerca.service.admin;

import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.security.ClientCertificatePrincipal;
import com.fidd.flowerca.service.CertificateIssuanceService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@ConditionalOnProperty(prefix = "flowerca.issuer", name = "enabled",
    havingValue = "true", matchIfMissing = true)
public class AdminCertificateRenewalService implements AdminCertificateRenewalUseCase {

  private final UserProfileRepository users;
  private final CertificateRepository certificates;
  private final CertificateIssuanceService issuance;
  private final AuditEventRepository audit;
  private final CertificateChainPemEncoder pemEncoder;

  public AdminCertificateRenewalService(
      UserProfileRepository users, CertificateRepository certificates,
      CertificateIssuanceService issuance, AuditEventRepository audit,
      CertificateChainPemEncoder pemEncoder) {
    this.users = users;
    this.certificates = certificates;
    this.issuance = issuance;
    this.audit = audit;
    this.pemEncoder = pemEncoder;
  }

  @Override
  @PreAuthorize("hasAuthority('ADMIN') and #actor == authentication.principal")
  @Transactional
  public AdminCertificateRenewal renew(
      RenewAdminCertificateCommand command, ClientCertificatePrincipal actor) {
    if (actor == null || actor.profileId() == null || actor.certificateId() == null) {
      throw new AccessDeniedException("Access denied");
    }
    // Lock the owner first: role/status changes must not race certificate issuance.
    var owner = users.findForUpdateById(actor.profileId())
        .orElseThrow(() -> new AccessDeniedException("Access denied"));
    CertificateEntity current = certificates.findForUpdateById(actor.certificateId())
        .orElseThrow(() -> new AccessDeniedException("Access denied"));
    Instant now = Instant.now();
    if (owner.getRole() != UserRole.ADMIN || owner.getStatus() != UserStatus.ACTIVE
        || current.getUserProfile() == null
        || !owner.getId().equals(current.getUserProfile().getId())
        || current.getProfile() != CertificateProfile.ADMIN_CLIENT
        || current.getStatus() != CertificateStatus.ACTIVE
        || current.getIssuer().getStatus() != CaIssuerStatus.ACTIVE
        || now.isBefore(current.getNotBefore()) || !now.isBefore(current.getNotAfter())
        || !MessageDigest.isEqual(current.getFingerprintSha256(), actor.certificateFingerprintSha256())) {
      throw new AccessDeniedException("Access denied");
    }

    var result = issuance.issueAdminClient(command.csrPem(), owner);
    var issued = result.issuedCertificate();
    String chain = new String(pemEncoder.encode(issued.fullChain()), StandardCharsets.US_ASCII);
    audit.save(new AuditEventEntity(
        owner.getId(), current.getId(), current.getFingerprintSha256(),
        AuditAction.ADMIN_CERTIFICATE_RENEWED, AuditTargetType.CERTIFICATE,
        result.certificateId(), AuditResult.SUCCESS, null));
    // The transaction interceptor commits before the controller receives this result.
    return new AdminCertificateRenewal(result.certificateId(),
        issued.certificate().getNotBefore().toInstant(),
        issued.certificate().getNotAfter().toInstant(), chain);
  }
}
