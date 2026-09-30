package com.fidd.flowerca.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "admin_bootstrap_state")
public class AdminBootstrapStateEntity {

  @Id
  @Column(name = "name", nullable = false, length = 64)
  private String name;

  @OneToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_profile_id")
  private UserProfileEntity userProfile;

  @OneToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "certificate_id")
  private CertificateEntity certificate;

  @Column(name = "completed_at")
  private Instant completedAt;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected AdminBootstrapStateEntity() {}

  public AdminBootstrapStateEntity(String name) {
    this.name = name;
  }

  public void complete(
      UserProfileEntity userProfile, CertificateEntity certificate, Instant completedAt) {
    this.userProfile = userProfile;
    this.certificate = certificate;
    this.completedAt = completedAt;
  }

  public String getName() {
    return name;
  }

  public UserProfileEntity getUserProfile() {
    return userProfile;
  }

  public CertificateEntity getCertificate() {
    return certificate;
  }

  public Instant getCompletedAt() {
    return completedAt;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
