package com.fidd.flowerca.service.admin;

import com.fidd.flowerca.persistence.model.CertificateEffectiveStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.query.CertificateRow;
import java.math.BigInteger;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

public record CertificateView(
    UUID id, Owner owner, Issuer issuer, String serialNumberHex, String fingerprintSha256Hex,
    CertificateProfile profile, CertificateStatus storedStatus,
    CertificateEffectiveStatus effectiveStatus, String subjectDn,
    Instant notBefore, Instant notAfter, Instant revokedAt, String revocationReason,
    Instant createdAt) {

  public record Owner(UUID id, String displayName, String email) {}
  public record Issuer(UUID id, String subjectDn) {}

  public static CertificateView from(CertificateRow row, Instant now) {
    return new CertificateView(row.id(), row.ownerId() == null ? null
        : new Owner(row.ownerId(), row.ownerDisplayName(), row.ownerEmail()),
        new Issuer(row.issuerId(), row.issuerSubjectDn()),
        new BigInteger(1, row.serialNumber()).toString(16),
        HexFormat.of().formatHex(row.fingerprintSha256()), row.profile(), row.status(),
        CertificateEffectiveStatus.at(row.status(), row.notBefore(), row.notAfter(), now),
        row.subjectDn(), row.notBefore(), row.notAfter(), row.revokedAt(),
        row.revocationReason(), row.createdAt());
  }
}
