package com.fidd.flowerca.security;

import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ClientCertificateAuthenticationService {

  private final CertificateRepository certificates;
  private final Clock clock;

  @Autowired
  public ClientCertificateAuthenticationService(CertificateRepository certificates) {
    this(certificates, Clock.systemUTC());
  }

  ClientCertificateAuthenticationService(CertificateRepository certificates, Clock clock) {
    this.certificates = certificates;
    this.clock = clock;
  }

  @Transactional(readOnly = true)
  public Optional<ClientCertificateAuthentication> authenticate(X509Certificate presented) {
    byte[] fingerprint = fingerprint(presented);
    return certificates
        .findWithUserProfileAndIssuerByFingerprintSha256(fingerprint)
        .filter(stored -> isConsistent(stored, presented))
        .filter(this::isCurrentlyUsable)
        .map(stored -> authentication(stored, fingerprint));
  }

  private boolean isConsistent(CertificateEntity stored, X509Certificate presented) {
    return Arrays.equals(stored.getSerialNumber(), unsigned(presented.getSerialNumber().toByteArray()))
        && new X500Principal(stored.getIssuer().getSubjectDn())
            .equals(presented.getIssuerX500Principal());
  }

  private boolean isCurrentlyUsable(CertificateEntity stored) {
    Instant now = clock.instant();
    return stored.getStatus() == CertificateStatus.ACTIVE
        && stored.getIssuer().getStatus() == CaIssuerStatus.ACTIVE
        && !now.isBefore(stored.getNotBefore())
        && now.isBefore(stored.getNotAfter());
  }

  private ClientCertificateAuthentication authentication(
      CertificateEntity stored, byte[] fingerprint) {
    UserProfileEntity owner = stored.getUserProfile();
    UUID profileId = owner == null ? null : owner.getId();
    boolean administrator =
        stored.getProfile() == CertificateProfile.ADMIN_CLIENT
            && owner != null
            && owner.getStatus() == UserStatus.ACTIVE
            && owner.getRole() == UserRole.ADMIN;
    return new ClientCertificateAuthentication(
        new ClientCertificatePrincipal(stored.getId(), profileId, fingerprint), administrator);
  }

  private byte[] fingerprint(X509Certificate certificate) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    } catch (CertificateEncodingException | NoSuchAlgorithmException exception) {
      throw new CertificateAuthenticationException(
          "Unable to identify presented client certificate", exception);
    }
  }

  private byte[] unsigned(byte[] value) {
    if (value.length > 1 && value[0] == 0) {
      return Arrays.copyOfRange(value, 1, value.length);
    }
    return value;
  }
}
