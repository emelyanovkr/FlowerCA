package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;

public interface CertificateRepository extends JpaRepository<CertificateEntity, UUID> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @EntityGraph(attributePaths = {"userProfile", "issuer"})
  @Query("select c from CertificateEntity c where c.id = :id")
  Optional<CertificateEntity> findForUpdateById(@Param("id") UUID id);

  Optional<CertificateEntity> findByIssuer_IdAndSerialNumber(UUID issuerId, byte[] serialNumber);

  Optional<CertificateEntity> findByFingerprintSha256(byte[] fingerprintSha256);

  @EntityGraph(attributePaths = {"userProfile", "issuer"})
  Optional<CertificateEntity> findWithUserProfileAndIssuerByFingerprintSha256(
      byte[] fingerprintSha256);

  List<CertificateEntity> findAllByUserProfile_IdAndStatus(
      UUID userProfileId, CertificateStatus status);
}
