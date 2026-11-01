package com.fidd.flowerca.persistence.repository;

import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.query.CertificateRow;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CertificateRepository extends JpaRepository<CertificateEntity, UUID> {

  String METADATA_SELECT = """
      select new com.fidd.flowerca.persistence.query.CertificateRow(
        c.id, u.id, u.displayName, u.email, i.id, i.subjectDn,
        c.serialNumber, c.fingerprintSha256, c.profile, c.status, c.subjectDn,
        c.notBefore, c.notAfter, c.revokedAt, c.revocationReason, c.createdAt)
      from CertificateEntity c left join c.userProfile u join c.issuer i
      """;

  String METADATA_FILTERS = """
      where (:ownerId is null or u.id = :ownerId)
        and (:profile is null or c.profile = :profile)
        and (:effectiveStatus is null or :effectiveStatus = case
          when c.status = com.fidd.flowerca.persistence.model.CertificateStatus.REVOKED then 'REVOKED'
          when c.status = com.fidd.flowerca.persistence.model.CertificateStatus.EXPIRED
            or c.notAfter <= :now then 'EXPIRED'
          when c.notBefore > :now then 'NOT_YET_VALID'
          else 'ACTIVE' end)
      """;

  @Query(value = METADATA_SELECT + METADATA_FILTERS,
      countQuery = "select count(c) from CertificateEntity c left join c.userProfile u " + METADATA_FILTERS)
  Page<CertificateRow> findMetadataPage(
      @Param("ownerId") UUID ownerId, @Param("profile") CertificateProfile profile,
      @Param("effectiveStatus") String effectiveStatus, @Param("now") Instant now, Pageable pageable);

  @Query(METADATA_SELECT + "where c.id = :id")
  Optional<CertificateRow> findMetadataById(@Param("id") UUID id);

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
