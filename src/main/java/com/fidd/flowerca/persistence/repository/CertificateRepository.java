package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<CertificateEntity, UUID> {

  Optional<CertificateEntity> findByIssuer_IdAndSerialNumber(UUID issuerId, byte[] serialNumber);

  Optional<CertificateEntity> findByFingerprintSha256(byte[] fingerprintSha256);

  List<CertificateEntity> findAllByUserProfile_IdAndStatus(
      UUID userProfileId, CertificateStatus status);
}
