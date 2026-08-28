package com.fidd.flowerca.testsupport;

import com.fidd.flowerca.issuer.IssuerIdentity;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public final class TestPki {

  private final KeyPair clientKeyPair;
  private final X509Certificate intermediateCertificate;
  private final X509Certificate rootCertificate;
  private final IssuerIdentity issuerIdentity;

  private TestPki(
      KeyPair clientKeyPair,
      X509Certificate intermediateCertificate,
      X509Certificate rootCertificate,
      IssuerIdentity issuerIdentity) {
    this.clientKeyPair = clientKeyPair;
    this.intermediateCertificate = intermediateCertificate;
    this.rootCertificate = rootCertificate;
    this.issuerIdentity = issuerIdentity;
  }

  public static TestPki create() throws Exception {
    KeyPair rootKeyPair = rsaKeyPair();
    KeyPair intermediateKeyPair = rsaKeyPair();
    KeyPair clientKeyPair = rsaKeyPair();
    Instant now = Instant.now();

    X500Name rootName = new X500Name("CN=FlowerCA Test Root CA,O=FlowerCA,C=RU");
    X509Certificate rootCertificate =
        createCaCertificate(
            rootName, rootName, BigInteger.ONE, rootKeyPair, rootKeyPair, 1, now);
    X500Name intermediateName =
        new X500Name("CN=FlowerCA Test Intermediate CA,O=FlowerCA,C=RU");
    X509Certificate intermediateCertificate =
        createCaCertificate(
            rootName,
            intermediateName,
            BigInteger.TWO,
            intermediateKeyPair,
            rootKeyPair,
            0,
            now);
    IssuerIdentity issuerIdentity =
        new IssuerIdentity(
            intermediateKeyPair.getPrivate(),
            intermediateCertificate,
            List.of(intermediateCertificate, rootCertificate));
    return new TestPki(
        clientKeyPair, intermediateCertificate, rootCertificate, issuerIdentity);
  }

  public String createCsrPem(String... dnsNames) throws Exception {
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

  public IssuerIdentity issuerIdentity() {
    return issuerIdentity;
  }

  public KeyPair clientKeyPair() {
    return clientKeyPair;
  }

  public X509Certificate intermediateCertificate() {
    return intermediateCertificate;
  }

  public X509Certificate rootCertificate() {
    return rootCertificate;
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  private static X509Certificate createCaCertificate(
      X500Name issuer,
      X500Name subject,
      BigInteger serial,
      KeyPair subjectKeys,
      KeyPair issuerKeys,
      int pathLength,
      Instant now)
      throws Exception {
    Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
    Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));
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
}
