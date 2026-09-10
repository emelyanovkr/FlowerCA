package com.fidd.flowerca.persistence.entity;

import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "audit_events")
public class AuditEventEntity extends AbstractUuidEntity {

  @JdbcTypeCode(SqlTypes.BINARY)
  @Column(name = "actor_profile_id", columnDefinition = "BINARY(16)")
  private UUID actorProfileId;

  @JdbcTypeCode(SqlTypes.BINARY)
  @Column(name = "actor_certificate_id", columnDefinition = "BINARY(16)")
  private UUID actorCertificateId;

  @Enumerated(EnumType.STRING)
  @Column(name = "action", nullable = false, length = 64)
  private AuditAction action;

  @Enumerated(EnumType.STRING)
  @Column(name = "target_type", nullable = false, length = 64)
  private AuditTargetType targetType;

  @JdbcTypeCode(SqlTypes.BINARY)
  @Column(name = "target_id", columnDefinition = "BINARY(16)")
  private UUID targetId;

  @Enumerated(EnumType.STRING)
  @Column(name = "result", nullable = false, length = 32)
  private AuditResult result;

  @Column(name = "details", columnDefinition = "JSON")
  private String details;

  @CreationTimestamp
  @Column(name = "occurred_at", nullable = false, updatable = false)
  private Instant occurredAt;

  protected AuditEventEntity() {}

  public AuditEventEntity(
      UUID actorProfileId,
      UUID actorCertificateId,
      AuditAction action,
      AuditTargetType targetType,
      UUID targetId,
      AuditResult result,
      String details) {
    this.actorProfileId = actorProfileId;
    this.actorCertificateId = actorCertificateId;
    this.action = action;
    this.targetType = targetType;
    this.targetId = targetId;
    this.result = result;
    this.details = details;
  }

  public UUID getActorProfileId() {
    return actorProfileId;
  }

  public UUID getActorCertificateId() {
    return actorCertificateId;
  }

  public AuditAction getAction() {
    return action;
  }

  public AuditTargetType getTargetType() {
    return targetType;
  }

  public UUID getTargetId() {
    return targetId;
  }

  public AuditResult getResult() {
    return result;
  }

  public String getDetails() {
    return details;
  }

  public Instant getOccurredAt() {
    return occurredAt;
  }
}
