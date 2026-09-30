package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.UserRole;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserProfileRepository extends JpaRepository<UserProfileEntity, UUID> {

  Optional<UserProfileEntity> findByEmailIgnoreCase(String email);

  boolean existsByRole(UserRole role);
}
