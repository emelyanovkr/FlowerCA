package com.fidd.flowerca.certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.policy.CertificatePolicyException;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateIssuerTests {

  private static final Instant NOW = Instant.parse("2026-08-13T10:15:30Z");

  private KeyPair rootKeyPair;
  private KeyPair intermediateKeyPair;
  private KeyPair clientKeyPair;
  private X509Certificate intermediateCertificate;
  private X509Certificate rootCertificate;
  private CertificateIssuer certificateIssuer;

  @BeforeEach
  void setUp() throws Exception {
    rootKeyPair = rsaKeyPair(2048);
    intermediateKeyPair = rsaKeyPair(2048);
    clientKeyPair = rsaKeyPair(2048);

    X500Name rootName = new X500Name("CN=FlowerCA Test Root CA,O=FlowerCA,C=RU");
    rootCertificate =
        createCaCertificate(
            rootName, rootName, BigInteger.ONE, rootKeyPair, rootKeyPair, 1);

    X500Name intermediateName =
        new X500Name("CN=FlowerCA Test Intermediate CA,O=FlowerCA,C=RU");
    intermediateCertificate =
        createCaCertificate(
            rootName,
            intermediateName,
            BigInteger.TWO,
            intermediateKeyPair,
            rootKeyPair,
            0);

    IssuerIdentity identity =
        new IssuerIdentity(
            intermediateKeyPair.getPrivate(),
            intermediateCertificate,
            List.of(intermediateCertificate, rootCertificate));
    certificateIssuer =
        new CertificateIssuer(
            identity,
            new InternalCertificatePolicy(),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new SecureRandom());
  }

  @Test
  void issuesValidTlsServerCertificateFromCsr() throws Exception {
    String csrPem =
        createCsrPem(
            new X500Name("CN=spoofed.example,O=Untrusted"),
            "spoofed.example");
    ParsedCsr parsedCsr = new CsrParser().parse(csrPem);
    CertificateIdentity.TlsServer identity =
        new CertificateIdentity.TlsServer(
            List.of("service-a.internal", "api.team.internal"));

    IssuedCertificate issued =
        certificateIssuer.issue(parsedCsr, CertificateProfile.TLS_SERVER, identity);

    X509Certificate certificate = issued.certificate();

    assertThat(certificate.getSubjectX500Principal())
        .isEqualTo(new X500Principal("CN=service-a.internal"));
    assertThat(certificate.getIssuerX500Principal())
        .isEqualTo(intermediateCertificate.getSubjectX500Principal());
    assertThat(certificate.getPublicKey().getEncoded())
        .isEqualTo(clientKeyPair.getPublic().getEncoded());
    assertThat(certificate.getSerialNumber()).isPositive();
    assertThat(certificate.getSerialNumber().toByteArray()).hasSizeLessThanOrEqualTo(20);
    assertThat(certificate.getNotBefore())
        .isEqualTo(Date.from(NOW.minus(CertificateIssuer.CLOCK_SKEW)));
    assertThat(certificate.getNotAfter())
        .isEqualTo(Date.from(NOW.plus(java.time.Duration.ofDays(30))));

    assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
    assertThat(certificate.getKeyUsage()[0]).isTrue(); // digitalSignature
    assertThat(certificate.getKeyUsage()[2]).isTrue(); // keyEncipherment
    assertThat(certificate.getExtendedKeyUsage())
        .containsExactly(KeyPurposeId.id_kp_serverAuth.getId());
    assertThat(dnsSubjectAlternativeNames(certificate))
        .containsExactly("service-a.internal", "api.team.internal");

    certificate.verify(intermediateCertificate.getPublicKey());
    intermediateCertificate.verify(rootCertificate.getPublicKey());
    assertThat(issued.fullChain())
        .containsExactly(certificate, intermediateCertificate, rootCertificate);
  }

  @Test
  void refusesToIssueCertificateRejectedByPolicy() throws Exception {
    ParsedCsr parsedCsr = new CsrParser().parse(createCsrPem("example.com"));

    assertThatThrownBy(
            () ->
                certificateIssuer.issue(
                    parsedCsr,
                    CertificateProfile.TLS_SERVER,
                    new CertificateIdentity.TlsServer(List.of("example.com"))))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: example.com");
  }

  @Test
  void issuesAdminClientIdentityWithoutTrustingCsrClaims() throws Exception {
    ParsedCsr parsedCsr =
        new CsrParser()
            .parse(
                createCsrPem(
                    new X500Name("CN=Mallory,O=Untrusted"),
                    "attacker.internal"));
    UUID profileId = UUID.fromString("d48f9ec8-18bd-43af-995d-3b7e51ced4f6");
    CertificateIdentity.User identity =
        new CertificateIdentity.User(
            profileId, "Alice Admin", "Alice.Admin@example.internal");

    IssuedCertificate issued =
        certificateIssuer.issue(
            parsedCsr, CertificateProfile.ADMIN_CLIENT, identity);
    X509Certificate certificate = issued.certificate();

    assertThat(certificate.getSubjectX500Principal())
        .isEqualTo(new X500Principal("CN=Alice Admin"));
    assertThat(certificate.getSubjectX500Principal().getName())
        .doesNotContain("Mallory");
    assertThat(certificate.getKeyUsage()[0]).isTrue();
    assertThat(certificate.getKeyUsage()[2]).isFalse();
    assertThat(certificate.getExtendedKeyUsage())
        .containsExactly(KeyPurposeId.id_kp_clientAuth.getId());
    assertThat(subjectAlternativeNames(certificate, GeneralName.uniformResourceIdentifier))
        .containsExactly("urn:flowerca:user:" + profileId);
    assertThat(subjectAlternativeNames(certificate, GeneralName.rfc822Name))
        .containsExactly("alice.admin@example.internal");
    assertThat(dnsSubjectAlternativeNames(certificate)).isEmpty();
  }

  @Test
  void boundsLeafValidityByIntermediateExpiry() throws Exception {
    X500Name rootName = new X500Name(rootCertificate.getSubjectX500Principal().getName());
    X500Name intermediateName =
        new X500Name("CN=Short Lived Intermediate CA,O=FlowerCA,C=RU");
    Instant intermediateExpiry = NOW.plus(Duration.ofHours(12));
    X509Certificate shortLivedIntermediate =
        createCaCertificate(
            rootName,
            intermediateName,
            BigInteger.valueOf(3),
            intermediateKeyPair,
            rootKeyPair,
            0,
            NOW.minus(Duration.ofHours(1)),
            intermediateExpiry);
    CertificateIssuer shortLivedIssuer =
        new CertificateIssuer(
            new IssuerIdentity(
                intermediateKeyPair.getPrivate(),
                shortLivedIntermediate,
                List.of(shortLivedIntermediate, rootCertificate)),
            new InternalCertificatePolicy(),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new SecureRandom());
    ParsedCsr parsedCsr = new CsrParser().parse(createCsrPem("csr.internal"));

    IssuedCertificate issued =
        shortLivedIssuer.issue(
            parsedCsr,
            CertificateProfile.TLS_SERVER,
            new CertificateIdentity.TlsServer(List.of("service.internal")));

    assertThat(issued.certificate().getNotAfter())
        .isEqualTo(Date.from(intermediateExpiry));
  }

  @Test
  void selectsSigningAlgorithmFromEcIntermediateKey() throws Exception {
    KeyPair ecIntermediateKeys = ecKeyPair();
    X500Name rootName = new X500Name(rootCertificate.getSubjectX500Principal().getName());
    X500Name intermediateName =
        new X500Name("CN=EC Intermediate CA,O=FlowerCA,C=RU");
    X509Certificate ecIntermediate =
        createCaCertificate(
            rootName,
            intermediateName,
            BigInteger.valueOf(4),
            ecIntermediateKeys,
            rootKeyPair,
            0);
    CertificateIssuer ecIssuer =
        new CertificateIssuer(
            new IssuerIdentity(
                ecIntermediateKeys.getPrivate(),
                ecIntermediate,
                List.of(ecIntermediate, rootCertificate)),
            new InternalCertificatePolicy(),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new SecureRandom());
    ParsedCsr parsedCsr = new CsrParser().parse(createCsrPem("csr.internal"));

    X509Certificate certificate =
        ecIssuer
            .issue(
                parsedCsr,
                CertificateProfile.TLS_SERVER,
                new CertificateIdentity.TlsServer(List.of("service.internal")))
            .certificate();

    assertThat(certificate.getSigAlgName()).isEqualTo("SHA256withECDSA");
    certificate.verify(ecIntermediate.getPublicKey());
  }

  @Test
  void usesSeparateProfileLifetimes() throws Exception {
    var lifetimes = new CertificateLifetimeProperties();
    lifetimes.setTlsServer(Duration.ofDays(7));
    lifetimes.setUserClient(Duration.ofDays(14));
    lifetimes.setAdminClient(Duration.ofDays(90));
    var issuer = new CertificateIssuer(
        new IssuerIdentity(intermediateKeyPair.getPrivate(), intermediateCertificate,
            List.of(intermediateCertificate, rootCertificate)),
        new InternalCertificatePolicy(), Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(), lifetimes);
    var csr = new CsrParser().parse(createCsrPem("untrusted.internal"));
    for (CertificateProfile profile : CertificateProfile.values()) {
      CertificateIdentity identity = profile == CertificateProfile.TLS_SERVER
          ? new CertificateIdentity.TlsServer(List.of("service.internal"))
          : new CertificateIdentity.User(UUID.randomUUID(), "Admin", "admin@example.internal");
      assertThat(issuer.issue(csr, profile, identity).certificate().getNotAfter().toInstant())
          .isEqualTo(NOW.plus(lifetimes.forProfile(profile)));
    }
  }

  @Test
  void configuredAdminLifetimeStillCannotExceedIntermediateExpiry() throws Exception {
    var lifetimes = new CertificateLifetimeProperties();
    lifetimes.setAdminClient(Duration.ofDays(500));
    var issuer = new CertificateIssuer(
        new IssuerIdentity(intermediateKeyPair.getPrivate(), intermediateCertificate,
            List.of(intermediateCertificate, rootCertificate)),
        new InternalCertificatePolicy(), Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(), lifetimes);
    var issued = issuer.issue(new CsrParser().parse(createCsrPem("ignored.internal")),
        CertificateProfile.ADMIN_CLIENT,
        new CertificateIdentity.User(UUID.randomUUID(), "Admin", "admin@example.internal"));
    assertThat(issued.certificate().getNotAfter()).isEqualTo(intermediateCertificate.getNotAfter());
  }

  private KeyPair rsaKeyPair(int size) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(size);
    return generator.generateKeyPair();
  }

  private KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    return generator.generateKeyPair();
  }

  private X509Certificate createCaCertificate(
      X500Name issuer,
      X500Name subject,
      BigInteger serial,
      KeyPair subjectKeys,
      KeyPair issuerKeys,
      int pathLength)
      throws Exception {
    return createCaCertificate(
        issuer,
        subject,
        serial,
        subjectKeys,
        issuerKeys,
        pathLength,
        NOW.minusSeconds(3600),
        NOW.plusSeconds(365L * 24 * 60 * 60));
  }

  private X509Certificate createCaCertificate(
      X500Name issuer,
      X500Name subject,
      BigInteger serial,
      KeyPair subjectKeys,
      KeyPair issuerKeys,
      int pathLength,
      Instant notBefore,
      Instant notAfter)
      throws Exception {
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            Date.from(notBefore),
            Date.from(notAfter),
            subject,
            subjectKeys.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  private String createCsrPem(String... dnsNames) throws Exception {
    return createCsrPem(
        new X500Name("CN=service-a.internal,O=FlowerCA Client,C=RU"),
        dnsNames);
  }

  private String createCsrPem(X500Name subject, String... dnsNames) throws Exception {
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(subject, clientKeyPair.getPublic());

    GeneralName[] names = new GeneralName[dnsNames.length];
    for (int index = 0; index < dnsNames.length; index++) {
      names[index] = new GeneralName(GeneralName.dNSName, dnsNames[index]);
    }
    ExtensionsGenerator extensions = new ExtensionsGenerator();
    extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
    builder.addAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(clientKeyPair.getPrivate());
    PKCS10CertificationRequest request = builder.build(signer);

    StringWriter output = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(output)) {
      writer.writeObject(request);
    }
    return output.toString();
  }

  private List<String> dnsSubjectAlternativeNames(X509Certificate certificate) throws Exception {
    return subjectAlternativeNames(certificate, GeneralName.dNSName);
  }

  private List<String> subjectAlternativeNames(X509Certificate certificate, int type)
      throws Exception {
    Collection<List<?>> names = certificate.getSubjectAlternativeNames();
    if (names == null) {
      return List.of();
    }
    return names.stream()
        .filter(name -> ((Integer) name.getFirst()) == type)
        .map(name -> (String) name.get(1))
        .toList();
  }
}
