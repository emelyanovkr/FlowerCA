package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.AdminBootstrapStateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminBootstrapStateRepository
    extends JpaRepository<AdminBootstrapStateEntity, String> {}
