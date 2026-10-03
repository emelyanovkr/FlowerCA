package com.fidd.flowerca.testsupport;

import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Development-only PKI. Server files never contain a client or Root private key. */
public final class TlsTestMaterial implements AutoCloseable {

  private static final List<String> FILES =
      List.of("issuer.p12", "root.pem", "server.p12", "client-trust.p12");
  private final Path directory;
  private final String password = UUID.randomUUID().toString();
  private final TestPki pki;
  private final Thread cleanupHook;

  private TlsTestMaterial(Path directory, TestPki pki) {
    this.directory = directory;
    this.pki = pki;
    // Spring can fail before JUnit invokes @AfterAll (e.g. Docker is unavailable).
    cleanupHook = new Thread(this::cleanupOnShutdown, "flowerca-test-pki-cleanup");
    Runtime.getRuntime().addShutdownHook(cleanupHook);
  }

  public static TlsTestMaterial create() throws Exception {
    TestPki pki = TestPki.create();
    var material = new TlsTestMaterial(Files.createTempDirectory("flowerca-tls-test-"), pki);
    try {
      material.writeIdentity("issuer.p12", "test-issuer", pki.issuerIdentity().privateKey(),
          pki.issuerIdentity().chain());
      Files.write(material.path("root.pem"),
          new CertificateChainPemEncoder().encode(List.of(pki.rootCertificate())));
      KeyPair serverKeys = newKeyPair();
      material.writeIdentity("server.p12", "https-server", serverKeys.getPrivate(),
          List.of(serverCertificate(pki, serverKeys), pki.intermediateCertificate(), pki.rootCertificate()));
      KeyStore trust = emptyStore();
      trust.setCertificateEntry("client-ca", pki.rootCertificate());
      material.writeStore("client-trust.p12", trust);
      return material;
    } catch (Exception exception) {
      material.close();
      throw exception;
    }
  }

  public TestPki pki() { return pki; }
  public String password() { return password; }
  public Path path(String name) { return directory.resolve(name); }

  public static KeyPair newKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  public static KeyStore emptyStore() throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    return store;
  }

  private void writeIdentity(String file, String alias, PrivateKey key,
      List<X509Certificate> chain) throws Exception {
    KeyStore store = emptyStore();
    store.setKeyEntry(alias, key, password.toCharArray(), chain.toArray(Certificate[]::new));
    writeStore(file, store);
  }

  private void writeStore(String file, KeyStore store) throws Exception {
    try (var output = Files.newOutputStream(path(file))) {
      store.store(output, password.toCharArray());
    }
  }

  private static X509Certificate serverCertificate(TestPki pki, KeyPair keys) throws Exception {
    Instant now = Instant.now();
    // Localhost is a test transport fixture, NOT a relaxation of the production .internal policy.
    var builder = new JcaX509v3CertificateBuilder(pki.intermediateCertificate(),
        new BigInteger(159, new SecureRandom()).setBit(158),
        Date.from(now.minus(1, ChronoUnit.HOURS)), Date.from(now.plus(7, ChronoUnit.DAYS)),
        new X500Name("CN=localhost"), keys.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    builder.addExtension(Extension.extendedKeyUsage, false,
        new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    builder.addExtension(Extension.subjectAlternativeName, false,
        new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
    var signer = new JcaContentSignerBuilder("SHA256withRSA").build(pki.issuerIdentity().privateKey());
    X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    certificate.verify(pki.intermediateCertificate().getPublicKey());
    return certificate;
  }

  @Override
  public synchronized void close() throws java.io.IOException {
    for (String file : FILES) {
      Files.deleteIfExists(path(file));
    }
    Files.deleteIfExists(directory);
    if (Thread.currentThread() != cleanupHook) {
      try {
        Runtime.getRuntime().removeShutdownHook(cleanupHook);
      } catch (IllegalStateException ignored) {
        // The test worker is already shutting down; the hook still performs idempotent cleanup.
      }
    }
  }

  private void cleanupOnShutdown() {
    try {
      close();
    } catch (java.io.IOException exception) {
      System.err.println("Temporary TLS test material could not be removed");
    }
  }

  @Override
  public String toString() { return "TlsTestMaterial[development-only]"; }
}
