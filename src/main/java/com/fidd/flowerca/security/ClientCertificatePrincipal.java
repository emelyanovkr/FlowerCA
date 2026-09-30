package com.fidd.flowerca.security;

import java.security.Principal;
import java.util.Objects;
import java.util.UUID;

public record ClientCertificatePrincipal(
    UUID certificateId,
    UUID profileId,
    byte[] certificateFingerprintSha256)
    implements Principal {

  public ClientCertificatePrincipal {
    Objects.requireNonNull(certificateId, "certificateId");
    Objects.requireNonNull(certificateFingerprintSha256, "certificateFingerprintSha256");
    certificateFingerprintSha256 = certificateFingerprintSha256.clone();
  }

  @Override
  public byte[] certificateFingerprintSha256() {
    return certificateFingerprintSha256.clone();
  }

  @Override
  public String getName() {
    return certificateId.toString();
  }
}
