package com.fidd.flowerca.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;

class Pkcs12IssuerIdentityLoaderTests {

  private static final String ALIAS = "flowerca-intermediate";
  private static final String PASSWORD = "changeit";

  private final Pkcs12IssuerIdentityLoader loader = new Pkcs12IssuerIdentityLoader();

  @TempDir Path tempDirectory;

  @Test
  void loadsValidIntermediateIdentity() throws Exception {
    TestCaFiles files = createTestCaFiles("valid");

    IssuerIdentity identity = loader.load(properties(files, PASSWORD, ALIAS));

    assertThat(identity.privateKey().getAlgorithm()).isEqualTo("RSA");
    assertThat(identity.certificate().getSubjectX500Principal().getName())
        .contains("CN=FlowerCA Test Intermediate");
    assertThat(identity.chain()).hasSize(2);
  }

  @Test
  void rejectsWrongPassword() throws Exception {
    TestCaFiles files = createTestCaFiles("wrong-password");
    IssuerProperties properties = properties(files, "incorrect-password", ALIAS);

    assertThatThrownBy(() -> loader.load(properties))
        .isInstanceOf(IssuerIdentityException.class)
        .hasMessage("Unable to load Intermediate CA identity");
  }

  @Test
  void rejectsMissingAlias() throws Exception {
    TestCaFiles files = createTestCaFiles("missing-alias");
    IssuerProperties properties = properties(files, PASSWORD, "missing");

    assertThatThrownBy(() -> loader.load(properties))
        .isInstanceOf(IssuerIdentityException.class)
        .hasMessage("Intermediate CA alias not found: missing");
  }

  @Test
  void rejectsUnexpectedRoot() throws Exception {
    TestCaFiles files = createTestCaFiles("issuer");
    TestCaFiles otherCa = createTestCaFiles("other");
    IssuerProperties properties = properties(files, PASSWORD, ALIAS);
    properties.setTrustedRoot(new FileSystemResource(otherCa.rootCertificate()));

    assertThatThrownBy(() -> loader.load(properties))
        .isInstanceOf(IssuerIdentityException.class)
        .hasMessage(
            "Intermediate CA chain does not terminate at the configured trusted Root CA");
  }

  private IssuerProperties properties(TestCaFiles files, String password, String alias) {
    IssuerProperties properties = new IssuerProperties();
    properties.setKeyStore(new FileSystemResource(files.keyStore()));
    properties.setAlias(alias);
    properties.setPassword(password);
    properties.setTrustedRoot(new FileSystemResource(files.rootCertificate()));
    return properties;
  }

  private TestCaFiles createTestCaFiles(String prefix) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();

    Instant now = Instant.now();
    Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
    Date rootNotAfter = Date.from(now.plus(3650, ChronoUnit.DAYS));
    Date intermediateNotAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

    X500Name rootName = new X500Name("CN=FlowerCA Test Root,O=FlowerCA Development,C=RU");
    X509Certificate rootCertificate =
        createCertificate(
            rootName,
            rootName,
            BigInteger.ONE,
            notBefore,
            rootNotAfter,
            rootKeyPair,
            rootKeyPair,
            new BasicConstraints(1));

    X500Name intermediateName =
        new X500Name("CN=FlowerCA Test Intermediate,O=FlowerCA Development,C=RU");
    X509Certificate intermediateCertificate =
        createCertificate(
            rootName,
            intermediateName,
            BigInteger.TWO,
            notBefore,
            intermediateNotAfter,
            intermediateKeyPair,
            rootKeyPair,
            new BasicConstraints(0));

    Path keyStorePath = tempDirectory.resolve(prefix + "-intermediate.p12");
    Path rootCertificatePath = tempDirectory.resolve(prefix + "-root.der");

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    char[] password = PASSWORD.toCharArray();
    keyStore.load(null, password);
    keyStore.setKeyEntry(
        ALIAS,
        intermediateKeyPair.getPrivate(),
        password,
        new Certificate[] {intermediateCertificate, rootCertificate});
    try (OutputStream output = Files.newOutputStream(keyStorePath)) {
      keyStore.store(output, password);
    }
    Files.write(rootCertificatePath, rootCertificate.getEncoded());

    return new TestCaFiles(keyStorePath, rootCertificatePath);
  }

  private X509Certificate createCertificate(
      X500Name issuer,
      X500Name subject,
      BigInteger serialNumber,
      Date notBefore,
      Date notAfter,
      KeyPair subjectKeyPair,
      KeyPair issuerKeyPair,
      BasicConstraints basicConstraints)
      throws Exception {
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            serialNumber,
            notBefore,
            notAfter,
            subject,
            subjectKeyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, basicConstraints);
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
    certificate.verify(issuerKeyPair.getPublic());
    return certificate;
  }

  private record TestCaFiles(Path keyStore, Path rootCertificate) {}
}
