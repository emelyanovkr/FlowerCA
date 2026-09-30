package com.fidd.flowerca.certificate;

import com.fidd.flowerca.persistence.model.CertificateProfile;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public record IssuedCertificate(
    X509Certificate certificate,
    List<X509Certificate> issuerChain,
    CertificateProfile profile) {

  public IssuedCertificate {
    Objects.requireNonNull(certificate, "certificate");
    Objects.requireNonNull(profile, "profile");
    issuerChain = List.copyOf(issuerChain);
    if (issuerChain.isEmpty()) {
      throw new IllegalArgumentException("Issuer chain must not be empty");
    }
  }

  public List<X509Certificate> fullChain() {
    List<X509Certificate> result = new ArrayList<>(issuerChain.size() + 1);
    result.add(certificate);
    result.addAll(issuerChain);
    return List.copyOf(result);
  }
}
