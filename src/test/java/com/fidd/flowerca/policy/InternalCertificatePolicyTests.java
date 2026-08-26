package com.fidd.flowerca.policy;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fidd.flowerca.csr.ParsedCsr;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

class InternalCertificatePolicyTests {

  private final InternalCertificatePolicy policy = new InternalCertificatePolicy();

  @Test
  void acceptsRsa2048AndInternalDnsNames() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "service-a.internal", "api.team.internal");

    assertThatCode(() -> policy.validate(csr)).doesNotThrowAnyException();
  }

  @Test
  void rejectsCsrWithoutDnsSan() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("CSR must contain at least one DNS SAN");
  }

  @Test
  void rejectsDnsNameOutsideInternalZone() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "example.com");

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: example.com");
  }

  @Test
  void rejectsWildcardDnsName() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "*.internal");

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Wildcard DNS names are not supported: *.internal");
  }

  @Test
  void rejectsWeakRsaKey() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(1024), "service-a.internal");

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("RSA public key must be at least 2048 bits");
  }

  @Test
  void rejectsNonRsaKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    ParsedCsr csr = csr(generator.generateKeyPair().getPublic(), "service-a.internal");

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Only RSA public keys are supported");
  }

  @Test
  void rejectsDuplicateDnsNamesIgnoringCase() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "service-a.internal", "SERVICE-A.INTERNAL");

    assertThatThrownBy(() -> policy.validate(csr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Duplicate DNS SAN: SERVICE-A.INTERNAL");
  }

  private ParsedCsr csr(PublicKey publicKey, String... dnsNames) {
    return new ParsedCsr(
        new X500Principal("CN=service-a.internal"),
        publicKey,
        publicKey.getAlgorithm(),
        List.of(dnsNames));
  }

  private PublicKey rsaPublicKey(int keySize) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keySize);
    return generator.generateKeyPair().getPublic();
  }
}
