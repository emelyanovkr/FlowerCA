package com.fidd.flowerca.persistence.query;

import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import java.time.Instant;
import java.util.UUID;

// Scalar projection only: neither certificate/issuer DER nor managed entities are selected.
public record CertificateRow(
    UUID id, UUID ownerId, String ownerDisplayName, String ownerEmail,
    UUID issuerId, String issuerSubjectDn, byte[] serialNumber, byte[] fingerprintSha256,
    CertificateProfile profile, CertificateStatus status, String subjectDn,
    Instant notBefore, Instant notAfter, Instant revokedAt, String revocationReason,
    Instant createdAt) {}
