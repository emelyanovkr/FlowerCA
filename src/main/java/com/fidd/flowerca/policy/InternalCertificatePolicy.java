package com.fidd.flowerca.policy;

import com.fidd.flowerca.csr.ParsedCsr;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class InternalCertificatePolicy {

  static final int MINIMUM_RSA_KEY_SIZE = 2048;

  private static final String ALLOWED_DNS_SUFFIX = ".internal";
  private static final Pattern DNS_NAME =
      Pattern.compile(
          "(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+internal");

  public void validate(ParsedCsr csr) {
    if (csr == null) {
      throw new CertificatePolicyException("CSR must not be null");
    }

    validatePublicKey(csr);
    validateDnsNames(csr.dnsSubjectAlternativeNames());
  }

  private void validatePublicKey(ParsedCsr csr) {
    if (!(csr.publicKey() instanceof RSAPublicKey rsaPublicKey)) {
      throw new CertificatePolicyException("Only RSA public keys are supported");
    }

    int keySize = rsaPublicKey.getModulus().bitLength();
    if (keySize < MINIMUM_RSA_KEY_SIZE) {
      throw new CertificatePolicyException(
          "RSA public key must be at least " + MINIMUM_RSA_KEY_SIZE + " bits");
    }
  }

  private void validateDnsNames(List<String> dnsNames) {
    if (dnsNames.isEmpty()) {
      throw new CertificatePolicyException("CSR must contain at least one DNS SAN");
    }

    Set<String> uniqueNames = new HashSet<>();
    for (String dnsName : dnsNames) {
      String normalizedName = normalize(dnsName);
      if (normalizedName.startsWith("*.")) {
        throw new CertificatePolicyException("Wildcard DNS names are not supported: " + dnsName);
      }
      if (!normalizedName.endsWith(ALLOWED_DNS_SUFFIX)
          || !DNS_NAME.matcher(normalizedName).matches()) {
        throw new CertificatePolicyException(
            "DNS name must be a valid name inside .internal: " + dnsName);
      }
      if (!uniqueNames.add(normalizedName)) {
        throw new CertificatePolicyException("Duplicate DNS SAN: " + dnsName);
      }
    }
  }

  private String normalize(String dnsName) {
    if (dnsName == null || dnsName.isBlank()) {
      throw new CertificatePolicyException("DNS SAN must not be blank");
    }
    return dnsName.toLowerCase(Locale.ROOT);
  }
}
