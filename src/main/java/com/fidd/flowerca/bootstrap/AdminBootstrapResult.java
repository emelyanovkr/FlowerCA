package com.fidd.flowerca.bootstrap;

import com.fidd.flowerca.certificate.IssuedCertificate;
import java.util.Objects;
import java.util.UUID;

public record AdminBootstrapResult(
    UUID userProfileId,
    UUID certificateId,
    IssuedCertificate issuedCertificate,
    boolean created) {

  public AdminBootstrapResult {
    Objects.requireNonNull(userProfileId, "userProfileId");
    Objects.requireNonNull(certificateId, "certificateId");
    Objects.requireNonNull(issuedCertificate, "issuedCertificate");
  }
}
