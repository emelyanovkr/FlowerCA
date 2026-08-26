package com.fidd.flowerca.certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.policy.CertificatePolicyException;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
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

  private KeyPair clientKeyPair;
  private X509Certificate intermediateCertificate;
  private X509Certificate rootCertificate;
  private CertificateIssuer certificateIssuer;

  @BeforeEach
  void setUp() throws Exception {
    KeyPair rootKeyPair = rsaKeyPair(2048);
    KeyPair intermediateKeyPair = rsaKeyPair(2048);
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
    String csrPem = createCsrPem("service-a.internal", "api.team.internal");
    ParsedCsr parsedCsr = new CsrParser().parse(csrPem);

    IssuedCertificate issued = certificateIssuer.issue(parsedCsr);

    X509Certificate certificate = issued.certificate();

    assertThat(certificate.getSubjectX500Principal()).isEqualTo(parsedCsr.subject());
    assertThat(certificate.getIssuerX500Principal())
        .isEqualTo(intermediateCertificate.getSubjectX500Principal());
    assertThat(certificate.getPublicKey().getEncoded())
        .isEqualTo(clientKeyPair.getPublic().getEncoded());
    assertThat(certificate.getSerialNumber()).isPositive();
    assertThat(certificate.getSerialNumber().toByteArray()).hasSizeLessThanOrEqualTo(20);
    assertThat(certificate.getNotBefore())
        .isEqualTo(Date.from(NOW.minus(CertificateIssuer.CLOCK_SKEW)));
    assertThat(certificate.getNotAfter())
        .isEqualTo(Date.from(NOW.plus(CertificateIssuer.CERTIFICATE_LIFETIME)));

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

    assertThatThrownBy(() -> certificateIssuer.issue(parsedCsr))
        .isInstanceOf(CertificatePolicyException.class)
        .hasMessage("DNS name must be a valid name inside .internal: example.com");
  }

  private KeyPair rsaKeyPair(int size) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(size);
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
    Date notBefore = Date.from(NOW.minusSeconds(3600));
    Date notAfter = Date.from(NOW.plusSeconds(365L * 24 * 60 * 60));
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, subjectKeys.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  private String createCsrPem(String... dnsNames) throws Exception {
    X500Name subject = new X500Name("CN=service-a.internal,O=FlowerCA Client,C=RU");
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
    Collection<List<?>> names = certificate.getSubjectAlternativeNames();
    return names.stream()
        .filter(name -> ((Integer) name.getFirst()) == GeneralName.dNSName)
        .map(name -> (String) name.get(1))
        .toList();
  }
}
