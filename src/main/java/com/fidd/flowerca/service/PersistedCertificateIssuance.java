package com.fidd.flowerca.service;

import com.fidd.flowerca.certificate.IssuedCertificate;
import java.util.Objects;
import java.util.UUID;

public record PersistedCertificateIssuance(
    IssuedCertificate issuedCertificate, UUID certificateId) {

  public PersistedCertificateIssuance {
    Objects.requireNonNull(issuedCertificate, "issuedCertificate");
    Objects.requireNonNull(certificateId, "certificateId");
  }
}
