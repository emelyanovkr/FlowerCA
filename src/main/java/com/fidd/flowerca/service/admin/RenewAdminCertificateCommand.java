package com.fidd.flowerca.service.admin;

import com.fidd.flowerca.policy.CertificatePolicyException;

public record RenewAdminCertificateCommand(String csrPem) {

  public static final int MAX_CSR_LENGTH = 65536;

  public RenewAdminCertificateCommand {
    if (csrPem == null || csrPem.isBlank() || csrPem.length() > MAX_CSR_LENGTH) {
      throw new CertificatePolicyException("A bounded CSR is required");
    }
  }
}
