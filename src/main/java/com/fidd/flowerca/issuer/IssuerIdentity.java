package com.fidd.flowerca.issuer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record IssuerIdentity(
    PrivateKey privateKey, X509Certificate certificate, List<X509Certificate> chain) {

  public IssuerIdentity {
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(certificate, "certificate");
    chain = List.copyOf(chain);
    if (chain.isEmpty()) {
      throw new IllegalArgumentException("Certificate chain must not be empty");
    }
  }

  @Override
  @NonNull
  public String toString() {
    return "IssuerIdentity[subject="
        + certificate.getSubjectX500Principal().getName()
        + ", chainSize="
        + chain.size()
        + "]";
  }
}
