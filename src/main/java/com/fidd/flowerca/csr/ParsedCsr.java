package com.fidd.flowerca.csr;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

public record ParsedCsr(
    X500Principal subject,
    PublicKey publicKey,
    String publicKeyAlgorithm,
    List<String> dnsSubjectAlternativeNames) {

  public ParsedCsr {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(publicKey, "publicKey");
    Objects.requireNonNull(publicKeyAlgorithm, "publicKeyAlgorithm");
    dnsSubjectAlternativeNames = List.copyOf(dnsSubjectAlternativeNames);
  }
}
