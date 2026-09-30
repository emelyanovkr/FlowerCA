package com.fidd.flowerca.policy;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

class InternalCertificatePolicyTests {

  private final InternalCertificatePolicy policy = new InternalCertificatePolicy();

  @Test
  void acceptsRsa2048AndInternalDnsNames() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "untrusted-csr.internal");

    assertThatCode(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("service-a.internal", "api.team.internal")))
        .doesNotThrowAnyException();
  }

  @Test
  void rejectsTlsServerIdentityWithoutDnsSan() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity()))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("TLS server identity must contain at least one DNS SAN");
  }

  @Test
  void rejectsDnsNameOutsideInternalZone() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("example.com")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: example.com");
  }

  @Test
  void rejectsDnsLabelLongerThan63Characters() throws Exception {
    String dnsName = "a".repeat(64) + ".internal";
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity(dnsName)))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: " + dnsName);
  }

  @Test
  void rejectsDnsNameWithInvalidLabelCharacters() throws Exception {
    String dnsName = "service_a.internal";
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity(dnsName)))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: " + dnsName);
  }

  @Test
  void rejectsDnsNameLongerThan253Characters() throws Exception {
    String dnsName =
        String.join(".", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(55), "internal");
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity(dnsName)))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: " + dnsName);
  }

  @Test
  void rejectsWildcardDnsName() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("*.internal")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Wildcard DNS names are not supported: *.internal");
  }

  @Test
  void rejectsWeakRsaKey() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(1024));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("service-a.internal")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("RSA public key must be at least 2048 bits");
  }

  @Test
  void rejectsNonRsaKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    ParsedCsr csr = csr(generator.generateKeyPair().getPublic());

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("service-a.internal")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Only RSA public keys are supported");
  }

  @Test
  void rejectsDuplicateDnsNamesIgnoringCase() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity("service-a.internal", "SERVICE-A.INTERNAL")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Duplicate DNS SAN: SERVICE-A.INTERNAL");
  }

  @Test
  void acceptsApprovedAdminClientIdentityWithoutDnsNames() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048), "spoofed.internal");
    CertificateIdentity.User identity =
        new CertificateIdentity.User(
            UUID.randomUUID(), "Alice Admin", "alice@example.internal");

    assertThatCode(
            () ->
                policy.validate(
                    csr, CertificateProfile.ADMIN_CLIENT, identity))
        .doesNotThrowAnyException();
  }

  @Test
  void rejectsTlsIdentityForClientProfile() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.ADMIN_CLIENT,
                    tlsServerIdentity("service-a.internal")))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("Client certificate profiles require an approved user identity");
  }

  @Test
  void rejectsInvalidApprovedUserEmail() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));
    CertificateIdentity.User identity =
        new CertificateIdentity.User(UUID.randomUUID(), "Alice Admin", "not-an-email");

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr, CertificateProfile.ADMIN_CLIENT, identity))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("User email address is invalid");
  }

  @Test
  void rejectsDisplayNameLongerThanCommonNameLimit() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));
    CertificateIdentity.User identity =
        new CertificateIdentity.User(
            UUID.randomUUID(), "a".repeat(65), "alice@example.internal");

    assertThatThrownBy(
            () -> policy.validate(csr, CertificateProfile.ADMIN_CLIENT, identity))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("User display name is invalid");
  }

  @Test
  void rejectsFirstDnsNameLongerThanCommonNameLimit() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));
    String longCommonName = "a".repeat(40) + "." + "b".repeat(20) + ".internal";

    assertThatThrownBy(
            () ->
                policy.validate(
                    csr,
                    CertificateProfile.TLS_SERVER,
                    tlsServerIdentity(longCommonName)))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("First DNS name is too long for the certificate Subject CN");
  }

  @Test
  void rejectsEmailWithoutDnsDomain() throws Exception {
    ParsedCsr csr = csr(rsaPublicKey(2048));
    CertificateIdentity.User identity =
        new CertificateIdentity.User(UUID.randomUUID(), "Alice", "a@b");

    assertThatThrownBy(
            () -> policy.validate(csr, CertificateProfile.ADMIN_CLIENT, identity))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("User email address is invalid");
  }

  private ParsedCsr csr(PublicKey publicKey, String... dnsNames) {
    return new ParsedCsr(
        new X500Principal("CN=service-a.internal"),
        publicKey,
        publicKey.getAlgorithm(),
        List.of(dnsNames));
  }

  private CertificateIdentity.TlsServer tlsServerIdentity(String... dnsNames) {
    return new CertificateIdentity.TlsServer(List.of(dnsNames));
  }

  private PublicKey rsaPublicKey(int keySize) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keySize);
    return generator.generateKeyPair().getPublic();
  }
}
