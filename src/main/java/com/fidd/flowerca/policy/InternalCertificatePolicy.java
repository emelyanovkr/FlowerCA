package com.fidd.flowerca.policy;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.persistence.model.CertificateProfile;
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
  private static final int MAXIMUM_COMMON_NAME_LENGTH = 64;
  private static final int MAXIMUM_EMAIL_LENGTH = 254;

  public void validate(
      ParsedCsr csr, CertificateProfile profile, CertificateIdentity identity) {
    if (csr == null) {
      throw new CertificatePolicyException("CSR must not be null");
    }
    if (profile == null) {
      throw new CertificatePolicyException("Certificate profile must not be null");
    }
    if (identity == null) {
      throw new CertificatePolicyException("Certificate identity must not be null");
    }

    validatePublicKey(csr);
    switch (profile) {
      case TLS_SERVER -> validateTlsServerIdentity(identity);
      case USER_CLIENT, ADMIN_CLIENT -> validateUserIdentity(identity);
    }
  }

  private void validateTlsServerIdentity(CertificateIdentity identity) {
    if (!(identity instanceof CertificateIdentity.TlsServer tlsServer)) {
      throw new CertificatePolicyException(
          "TLS_SERVER requires an approved TLS server identity");
    }
    validateDnsNames(tlsServer.dnsNames());
  }

  private void validateUserIdentity(CertificateIdentity identity) {
    if (!(identity instanceof CertificateIdentity.User user)) {
      throw new CertificatePolicyException(
          "Client certificate profiles require an approved user identity");
    }
    if (user.profileId() == null) {
      throw new CertificatePolicyException("User profile ID must not be null");
    }
    validateUserProfile(user.displayName(), user.email());
  }

  public void validateUserProfile(String displayName, String email) {
    if (displayName == null || displayName.isBlank()) {
      throw new CertificatePolicyException("User display name must not be blank");
    }
    if (displayName.trim().length() > MAXIMUM_COMMON_NAME_LENGTH
        || displayName.chars().anyMatch(Character::isISOControl)) {
      throw new CertificatePolicyException("User display name is invalid");
    }
    validateEmail(email);
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
    if (dnsNames == null || dnsNames.isEmpty()) {
      throw new CertificatePolicyException(
          "TLS server identity must contain at least one DNS SAN");
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
    if (normalize(dnsNames.getFirst()).length() > MAXIMUM_COMMON_NAME_LENGTH) {
      throw new CertificatePolicyException(
          "First DNS name is too long for the certificate Subject CN");
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
    if (!isAsciiLetterOrDigit(label.charAt(0))
        || !isAsciiLetterOrDigit(label.charAt(label.length() - 1))) {
      return false;
    }

    for (int index = 1; index < label.length() - 1; index++) {
      char character = label.charAt(index);
      if (!isAsciiLetterOrDigit(character) && character != '-') {
        return false;
      }
    }
    return true;
  }

  private boolean isAsciiLetterOrDigit(char character) {
    return (character >= 'a' && character <= 'z')
        || (character >= '0' && character <= '9');
  }

  private String normalize(String dnsName) {
    if (dnsName == null || dnsName.isBlank()) {
      throw new CertificatePolicyException("DNS SAN must not be blank");
    }
    return dnsName.toLowerCase(Locale.ROOT);
  }

  private void validateEmail(String email) {
    if (email == null) {
      return;
    }
    String normalized = email.trim();
    if (normalized.isEmpty()
        || normalized.length() > MAXIMUM_EMAIL_LENGTH
        || !normalized.chars().allMatch(character -> character <= 0x7f)
        || normalized.chars().anyMatch(Character::isWhitespace)
        || normalized.indexOf('@') <= 0
        || normalized.indexOf('@') != normalized.lastIndexOf('@')) {
      throw new CertificatePolicyException("User email address is invalid");
    }
    String localPart = normalized.substring(0, normalized.indexOf('@'));
    String domain = normalized.substring(normalized.indexOf('@') + 1).toLowerCase(Locale.ROOT);
    if (localPart.length() > 64
        || localPart.startsWith(".")
        || localPart.endsWith(".")
        || localPart.contains("..")
        || !localPart.chars().allMatch(this::isValidEmailLocalCharacter)
        || !domain.contains(".")
        || !isValidDnsName(domain)) {
      throw new CertificatePolicyException("User email address is invalid");
    }
  }

  private boolean isValidEmailLocalCharacter(int character) {
    return isAsciiLetterOrDigit((char) Character.toLowerCase(character))
        || ".!#$%&'*+-/=?^_`{|}~".indexOf(character) >= 0;
  }
}
