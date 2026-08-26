package com.fidd.flowerca.persistence.entity;

import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(
    name = "certificates",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_certificates_issuer_serial",
          columnNames = {"issuer_id", "serial_number"}),
      @UniqueConstraint(
          name = "uk_certificates_fingerprint_sha256",
          columnNames = "fingerprint_sha256")
    })
public class CertificateEntity extends AbstractUuidEntity {

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_profile_id")
  private UserProfileEntity userProfile;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "issuer_id", nullable = false)
  private CaIssuerEntity issuer;

  @Column(name = "serial_number", nullable = false, length = 20)
  private byte[] serialNumber;

  @Column(name = "fingerprint_sha256", nullable = false, length = 32)
  private byte[] fingerprintSha256;

  @Enumerated(EnumType.STRING)
  @Column(name = "profile", nullable = false, length = 32)
  private CertificateProfile profile;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 32)
  private CertificateStatus status;

  @Column(name = "subject_dn", nullable = false, length = 1024)
  private String subjectDn;

  @Lob
  @Column(name = "certificate_der", nullable = false, columnDefinition = "MEDIUMBLOB")
  private byte[] certificateDer;

  @Column(name = "not_before", nullable = false)
  private Instant notBefore;

  @Column(name = "not_after", nullable = false)
  private Instant notAfter;

  @Column(name = "revoked_at")
  private Instant revokedAt;

  @Column(name = "revocation_reason", length = 64)
  private String revocationReason;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected CertificateEntity() {}

  public CertificateEntity(
      UserProfileEntity userProfile,
      CaIssuerEntity issuer,
      byte[] serialNumber,
      byte[] fingerprintSha256,
      CertificateProfile profile,
      String subjectDn,
      byte[] certificateDer,
      Instant notBefore,
      Instant notAfter) {
    this.userProfile = userProfile;
    this.issuer = issuer;
    this.serialNumber = serialNumber.clone();
    this.fingerprintSha256 = fingerprintSha256.clone();
    this.profile = profile;
    this.status = CertificateStatus.ACTIVE;
    this.subjectDn = subjectDn;
    this.certificateDer = certificateDer.clone();
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  public UserProfileEntity getUserProfile() {
    return userProfile;
  }

  public CaIssuerEntity getIssuer() {
    return issuer;
  }

  public byte[] getSerialNumber() {
    return serialNumber.clone();
  }

  public byte[] getFingerprintSha256() {
    return fingerprintSha256.clone();
  }

  public CertificateProfile getProfile() {
    return profile;
  }

  public CertificateStatus getStatus() {
    return status;
  }

  public String getSubjectDn() {
    return subjectDn;
  }

  public byte[] getCertificateDer() {
    return certificateDer.clone();
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public Instant getNotAfter() {
    return notAfter;
  }

  public Instant getRevokedAt() {
    return revokedAt;
  }

  public String getRevocationReason() {
    return revocationReason;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
