package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.model.CaIssuerStatus;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CaIssuerRepository extends JpaRepository<CaIssuerEntity, UUID> {

  Optional<CaIssuerEntity> findFirstByStatus(CaIssuerStatus status);
}
