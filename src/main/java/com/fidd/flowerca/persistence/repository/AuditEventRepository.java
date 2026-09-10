package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, UUID> {

  List<AuditEventEntity> findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
      AuditTargetType targetType, UUID targetId);
}
