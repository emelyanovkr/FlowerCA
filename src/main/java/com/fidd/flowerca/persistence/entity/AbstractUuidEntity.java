package com.fidd.flowerca.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.type.SqlTypes;

@MappedSuperclass
public abstract class AbstractUuidEntity {

  @Id
  @UuidGenerator
  @JdbcTypeCode(SqlTypes.BINARY)
  @Column(name = "id", nullable = false, updatable = false, columnDefinition = "BINARY(16)")
  private UUID id;

  protected AbstractUuidEntity() {}

  public UUID getId() {
    return id;
  }
}
