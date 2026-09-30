package com.fidd.flowerca.bootstrap;

import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.CurrentIssuerRegistry;
import com.fidd.flowerca.persistence.entity.AdminBootstrapStateEntity;
import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import com.fidd.flowerca.persistence.repository.AdminBootstrapStateRepository;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.service.PersistedCertificateIssuance;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import org.springframework.transaction.annotation.Transactional;

public class FirstAdminBootstrapService {

  static final String STATE_NAME = "first-admin";

  private final AdminBootstrapStateRepository bootstrapStates;
  private final UserProfileRepository userProfiles;
  private final CertificateRepository certificates;
  private final AuditEventRepository auditEvents;
  private final CurrentIssuerRegistry issuerRegistry;
  private final CertificateIssuanceService issuanceService;
  private final CsrParser csrParser;
  private final IssuerIdentity issuerIdentity;
  private final Clock clock;

  public FirstAdminBootstrapService(
      AdminBootstrapStateRepository bootstrapStates,
      UserProfileRepository userProfiles,
      CertificateRepository certificates,
      AuditEventRepository auditEvents,
      CurrentIssuerRegistry issuerRegistry,
      CertificateIssuanceService issuanceService,
      CsrParser csrParser,
      IssuerIdentity issuerIdentity) {
    this(
        bootstrapStates,
        userProfiles,
        certificates,
        auditEvents,
        issuerRegistry,
        issuanceService,
        csrParser,
        issuerIdentity,
        Clock.systemUTC());
  }

  FirstAdminBootstrapService(
      AdminBootstrapStateRepository bootstrapStates,
      UserProfileRepository userProfiles,
      CertificateRepository certificates,
      AuditEventRepository auditEvents,
      CurrentIssuerRegistry issuerRegistry,
      CertificateIssuanceService issuanceService,
      CsrParser csrParser,
      IssuerIdentity issuerIdentity,
      Clock clock) {
    this.bootstrapStates = bootstrapStates;
    this.userProfiles = userProfiles;
    this.certificates = certificates;
    this.auditEvents = auditEvents;
    this.issuerRegistry = issuerRegistry;
    this.issuanceService = issuanceService;
    this.csrParser = csrParser;
    this.issuerIdentity = issuerIdentity;
    this.clock = clock;
  }

  @Transactional
  public AdminBootstrapResult bootstrap(String displayName, String email, String csrPem) {
    String approvedDisplayName = requireText(displayName, "Admin display name is required");
    String approvedEmail = requireText(email, "Admin email is required").toLowerCase(Locale.ROOT);
    ParsedCsr parsedCsr = csrParser.parse(csrPem);

    return bootstrapStates
        .findById(STATE_NAME)
        .map(state -> existingResult(state, approvedDisplayName, approvedEmail, parsedCsr))
        .orElseGet(
            () -> createFirstAdmin(approvedDisplayName, approvedEmail, csrPem));
  }

  private AdminBootstrapResult createFirstAdmin(
      String displayName, String email, String csrPem) {
    if (userProfiles.existsByRole(UserRole.ADMIN)) {
      throw new AdminBootstrapException(
          "An administrator already exists without matching bootstrap state");
    }

    AdminBootstrapStateEntity state =
        bootstrapStates.saveAndFlush(new AdminBootstrapStateEntity(STATE_NAME));
    issuerRegistry.register(issuerIdentity);

    UserProfileEntity admin =
        userProfiles.saveAndFlush(new UserProfileEntity(displayName, email, UserRole.ADMIN));
    PersistedCertificateIssuance issuance = issuanceService.issueAdminClient(csrPem, admin);
    CertificateEntity certificate = certificates.getReferenceById(issuance.certificateId());
    auditEvents.save(
        new AuditEventEntity(
            null,
            null,
            null,
            AuditAction.ADMIN_BOOTSTRAPPED,
            AuditTargetType.USER_PROFILE,
            admin.getId(),
            AuditResult.SUCCESS,
            null));
    state.complete(admin, certificate, clock.instant());
    bootstrapStates.save(state);

    return new AdminBootstrapResult(
        admin.getId(), certificate.getId(), issuance.issuedCertificate(), true);
  }

  private AdminBootstrapResult existingResult(
      AdminBootstrapStateEntity state,
      String displayName,
      String email,
      ParsedCsr parsedCsr) {
    UserProfileEntity admin = state.getUserProfile();
    CertificateEntity certificate = state.getCertificate();
    if (admin == null || certificate == null || state.getCompletedAt() == null) {
      throw new AdminBootstrapException("First-admin bootstrap state is incomplete");
    }
    if (admin.getRole() != UserRole.ADMIN
        || admin.getStatus() != UserStatus.ACTIVE
        || !admin.getDisplayName().equals(displayName)
        || admin.getEmail() == null
        || !admin.getEmail().equalsIgnoreCase(email)) {
      throw new AdminBootstrapException(
          "Configured administrator does not match the completed bootstrap");
    }
    if (certificate.getProfile() != CertificateProfile.ADMIN_CLIENT
        || certificate.getStatus() != CertificateStatus.ACTIVE
        || certificate.getUserProfile() == null
        || !certificate.getUserProfile().getId().equals(admin.getId())) {
      throw new AdminBootstrapException("Completed bootstrap certificate is not an active admin certificate");
    }

    X509Certificate storedCertificate = decode(certificate.getCertificateDer());
    if (!Arrays.equals(
        storedCertificate.getPublicKey().getEncoded(), parsedCsr.publicKey().getEncoded())) {
      throw new AdminBootstrapException(
          "Configured CSR does not match the completed bootstrap certificate");
    }
    try {
      storedCertificate.verify(issuerIdentity.certificate().getPublicKey());
    } catch (GeneralSecurityException exception) {
      throw new AdminBootstrapException(
          "Completed bootstrap certificate does not match the configured issuer", exception);
    }

    IssuedCertificate issuedCertificate =
        new IssuedCertificate(
            storedCertificate, issuerIdentity.chain(), CertificateProfile.ADMIN_CLIENT);
    return new AdminBootstrapResult(
        admin.getId(), certificate.getId(), issuedCertificate, false);
  }

  private X509Certificate decode(byte[] certificateDer) {
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(certificateDer));
    } catch (CertificateException exception) {
      throw new AdminBootstrapException("Stored bootstrap certificate is invalid", exception);
    }
  }

  private String requireText(String value, String message) {
    if (value == null || value.isBlank()) {
      throw new AdminBootstrapException(message);
    }
    return value.trim();
  }
}
