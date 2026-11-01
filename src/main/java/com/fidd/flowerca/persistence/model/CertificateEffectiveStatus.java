package com.fidd.flowerca.persistence.model;

import java.time.Instant;

// Display/filter state; not a replacement for persisted status or authorization checks.
public enum CertificateEffectiveStatus {
  ACTIVE,
  NOT_YET_VALID,
  EXPIRED,
  REVOKED;

  public static CertificateEffectiveStatus at(
      CertificateStatus storedStatus, Instant notBefore, Instant notAfter, Instant now) {
    if (storedStatus == CertificateStatus.REVOKED) {
      return REVOKED;
    }
    if (storedStatus == CertificateStatus.EXPIRED || !now.isBefore(notAfter)) {
      return EXPIRED;
    }
    return now.isBefore(notBefore) ? NOT_YET_VALID : ACTIVE;
  }
}
