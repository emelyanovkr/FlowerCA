package com.fidd.flowerca.certificate;

import java.util.List;
import java.util.UUID;

public sealed interface CertificateIdentity {

  record TlsServer(List<String> dnsNames) implements CertificateIdentity {

    public TlsServer {
      dnsNames = dnsNames == null ? null : List.copyOf(dnsNames);
    }
  }

  record User(UUID profileId, String displayName, String email)
      implements CertificateIdentity {}
}
