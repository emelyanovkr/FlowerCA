package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.UserRole;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserProfileRepository extends JpaRepository<UserProfileEntity, UUID> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select u from UserProfileEntity u where u.id = :id")
  Optional<UserProfileEntity> findForUpdateById(@Param("id") UUID id);

  Optional<UserProfileEntity> findByEmailIgnoreCase(String email);

  boolean existsByRole(UserRole role);
}
