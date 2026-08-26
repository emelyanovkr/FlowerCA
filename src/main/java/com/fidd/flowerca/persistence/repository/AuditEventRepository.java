package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, UUID> {

  List<AuditEventEntity> findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
      String targetType, UUID targetId);
}
