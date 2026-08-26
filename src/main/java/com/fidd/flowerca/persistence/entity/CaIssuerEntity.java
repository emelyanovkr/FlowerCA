package com.fidd.flowerca.persistence.entity;

import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "ca_issuers")
public class CaIssuerEntity extends AbstractUuidEntity {

  @Column(name = "name", nullable = false, unique = true, length = 100)
  private String name;

  @Column(name = "subject_dn", nullable = false, length = 1024)
  private String subjectDn;

  @Column(name = "serial_number", nullable = false, length = 20)
  private byte[] serialNumber;

  @Column(name = "subject_key_identifier", nullable = false, length = 64)
  private byte[] subjectKeyIdentifier;

  @Lob
  @Column(name = "certificate_der", nullable = false, columnDefinition = "MEDIUMBLOB")
  private byte[] certificateDer;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 32)
  private CaIssuerStatus status;

  @Column(name = "not_before", nullable = false)
  private Instant notBefore;

  @Column(name = "not_after", nullable = false)
  private Instant notAfter;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected CaIssuerEntity() {}

  public CaIssuerEntity(
      String name,
      String subjectDn,
      byte[] serialNumber,
      byte[] subjectKeyIdentifier,
      byte[] certificateDer,
      Instant notBefore,
      Instant notAfter) {
    this.name = name;
    this.subjectDn = subjectDn;
    this.serialNumber = serialNumber.clone();
    this.subjectKeyIdentifier = subjectKeyIdentifier.clone();
    this.certificateDer = certificateDer.clone();
    this.status = CaIssuerStatus.ACTIVE;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  public String getName() {
    return name;
  }

  public String getSubjectDn() {
    return subjectDn;
  }

  public byte[] getSerialNumber() {
    return serialNumber.clone();
  }

  public byte[] getSubjectKeyIdentifier() {
    return subjectKeyIdentifier.clone();
  }

  public byte[] getCertificateDer() {
    return certificateDer.clone();
  }

  public CaIssuerStatus getStatus() {
    return status;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public Instant getNotAfter() {
    return notAfter;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
