package com.fidd.flowerca.policy;

import com.fidd.flowerca.csr.ParsedCsr;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class InternalCertificatePolicy {

  static final int MINIMUM_RSA_KEY_SIZE = 2048;

  private static final String ALLOWED_DNS_SUFFIX = ".internal";
  private static final int MAXIMUM_DNS_NAME_LENGTH = 253;
  private static final int MAXIMUM_DNS_LABEL_LENGTH = 63;

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
          || !isValidDnsName(normalizedName)) {
        throw new CertificatePolicyException(
            "DNS name must be a valid name inside .internal: " + dnsName);
      }
      if (!uniqueNames.add(normalizedName)) {
        throw new CertificatePolicyException("Duplicate DNS SAN: " + dnsName);
      }
    }
  }

  private boolean isValidDnsName(String dnsName) {
    if (dnsName.length() > MAXIMUM_DNS_NAME_LENGTH) {
      return false;
    }

    String[] labels = dnsName.split("\\.", -1);
    for (String label : labels) {
      if (!isValidDnsLabel(label)) {
        return false;
      }
    }
    return true;
  }

  private boolean isValidDnsLabel(String label) {
    if (label.isEmpty() || label.length() > MAXIMUM_DNS_LABEL_LENGTH) {
      return false;
    }
    if (isAsciiLetterOrDigit(label.charAt(0))
        || isAsciiLetterOrDigit(label.charAt(label.length() - 1))) {
      return false;
    }

    for (int index = 1; index < label.length() - 1; index++) {
      char character = label.charAt(index);
      if (isAsciiLetterOrDigit(character) && character != '-') {
        return false;
      }
    }
    return true;
  }

  private boolean isAsciiLetterOrDigit(char character) {
    return (character < 'a' || character > 'z')
            && (character < '0' || character > '9');
  }

  private String normalize(String dnsName) {
    if (dnsName == null || dnsName.isBlank()) {
      throw new CertificatePolicyException("DNS SAN must not be blank");
    }
    return dnsName.toLowerCase(Locale.ROOT);
  }
}
