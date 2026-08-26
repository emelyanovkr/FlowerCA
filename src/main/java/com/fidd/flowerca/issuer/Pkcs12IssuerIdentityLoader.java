package com.fidd.flowerca.issuer;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.springframework.core.io.Resource;

public class Pkcs12IssuerIdentityLoader {

  private static final int KEY_PAIR_PROBE_SIZE = 32;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public IssuerIdentity load(IssuerProperties properties) {
    requireConfigured(properties);

    char[] password = properties.getPassword().toCharArray();
    try {
      KeyStore keyStore = loadKeyStore(properties.getKeyStore(), password);
      PrivateKey privateKey = loadPrivateKey(keyStore, properties.getAlias(), password);
      List<X509Certificate> chain = loadCertificateChain(keyStore, properties.getAlias());
      X509Certificate issuerCertificate = chain.getFirst();
      X509Certificate trustedRoot = loadCertificate(properties.getTrustedRoot());

      validateIssuerCertificate(issuerCertificate);
      validateKeyPair(privateKey, issuerCertificate);
      validateChain(chain, trustedRoot);

      return new IssuerIdentity(privateKey, issuerCertificate, chain);
    } catch (IssuerIdentityException exception) {
      throw exception;
    } catch (GeneralSecurityException | IOException exception) {
      throw new IssuerIdentityException("Unable to load Intermediate CA identity", exception);
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  private void requireConfigured(IssuerProperties properties) {
    if (properties == null) {
      throw new IssuerIdentityException("Issuer configuration is missing");
    }
    requireResource(properties.getKeyStore(), "flowerca.issuer.key-store");
    requireText(properties.getAlias(), "flowerca.issuer.alias");
    requireText(properties.getPassword(), "flowerca.issuer.password");
    requireResource(properties.getTrustedRoot(), "flowerca.issuer.trusted-root");
  }

  private void requireResource(Resource resource, String propertyName) {
    if (resource == null || !resource.exists() || !resource.isReadable()) {
      throw new IssuerIdentityException(propertyName + " must reference a readable file");
    }
  }

  private void requireText(String value, String propertyName) {
    if (value == null || value.isBlank()) {
      throw new IssuerIdentityException(propertyName + " must not be blank");
    }
  }

  private KeyStore loadKeyStore(Resource resource, char[] password)
      throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream input = resource.getInputStream()) {
      keyStore.load(input, password);
    }
    return keyStore;
  }

  private PrivateKey loadPrivateKey(KeyStore keyStore, String alias, char[] password)
      throws GeneralSecurityException {
    if (!keyStore.containsAlias(alias)) {
      throw new IssuerIdentityException("Intermediate CA alias not found: " + alias);
    }
    if (!keyStore.isKeyEntry(alias)) {
      throw new IssuerIdentityException("Intermediate CA alias is not a private key entry: " + alias);
    }

    Key key = keyStore.getKey(alias, password);
    if (!(key instanceof PrivateKey privateKey)) {
      throw new IssuerIdentityException("Intermediate CA entry does not contain a private key");
    }
    return privateKey;
  }

  private List<X509Certificate> loadCertificateChain(KeyStore keyStore, String alias)
      throws GeneralSecurityException {
    Certificate[] certificates = keyStore.getCertificateChain(alias);
    if (certificates == null || certificates.length < 2) {
      throw new IssuerIdentityException(
          "Intermediate CA entry must contain the issuer certificate and its Root CA chain");
    }

    List<X509Certificate> chain = new ArrayList<>(certificates.length);
    for (Certificate certificate : certificates) {
      if (!(certificate instanceof X509Certificate x509Certificate)) {
        throw new IssuerIdentityException("Intermediate CA chain contains a non-X.509 certificate");
      }
      chain.add(x509Certificate);
    }
    return List.copyOf(chain);
  }

  private X509Certificate loadCertificate(Resource resource)
      throws GeneralSecurityException, IOException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    try (InputStream input = resource.getInputStream()) {
      Certificate certificate = certificateFactory.generateCertificate(input);
      if (!(certificate instanceof X509Certificate x509Certificate)) {
        throw new IssuerIdentityException("Trusted Root CA is not an X.509 certificate");
      }
      return x509Certificate;
    }
  }

  private void validateIssuerCertificate(X509Certificate certificate)
      throws GeneralSecurityException {
    certificate.checkValidity();

    if (certificate.getBasicConstraints() < 0) {
      throw new IssuerIdentityException("Intermediate certificate is not a CA certificate");
    }

    boolean[] keyUsage = certificate.getKeyUsage();
    int keyCertSignIndex = 5;
    if (keyUsage == null || keyUsage.length <= keyCertSignIndex || !keyUsage[keyCertSignIndex]) {
      throw new IssuerIdentityException("Intermediate certificate does not allow certificate signing");
    }
  }

  private void validateKeyPair(PrivateKey privateKey, X509Certificate certificate)
      throws GeneralSecurityException {
    String signatureAlgorithm = signatureAlgorithmFor(privateKey);
    byte[] probe = new byte[KEY_PAIR_PROBE_SIZE];
    SECURE_RANDOM.nextBytes(probe);

    Signature signer = Signature.getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(probe);
    byte[] signature = signer.sign();

    Signature verifier = Signature.getInstance(signatureAlgorithm);
    verifier.initVerify(certificate.getPublicKey());
    verifier.update(probe);
    if (!verifier.verify(signature)) {
      throw new IssuerIdentityException(
          "Intermediate private key does not match its certificate public key");
    }
  }

  private String signatureAlgorithmFor(PrivateKey privateKey) {
    return switch (privateKey.getAlgorithm()) {
      case "RSA" -> "SHA256withRSA";
      case "EC" -> "SHA256withECDSA";
      case "Ed25519" -> "Ed25519";
      case "Ed448" -> "Ed448";
      default ->
          throw new IssuerIdentityException(
              "Unsupported Intermediate private key algorithm: " + privateKey.getAlgorithm());
    };
  }

  private void validateChain(List<X509Certificate> chain, X509Certificate trustedRoot)
      throws GeneralSecurityException {
    trustedRoot.checkValidity();
    trustedRoot.verify(trustedRoot.getPublicKey());
    if (trustedRoot.getBasicConstraints() < 0) {
      throw new IssuerIdentityException("Configured trusted Root certificate is not a CA");
    }

    X509Certificate chainRoot = chain.getLast();
    if (!Arrays.equals(chainRoot.getEncoded(), trustedRoot.getEncoded())) {
      throw new IssuerIdentityException(
          "Intermediate CA chain does not terminate at the configured trusted Root CA");
    }

    List<X509Certificate> pathCertificates = chain.subList(0, chain.size() - 1);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    CertPath certificatePath = certificateFactory.generateCertPath(pathCertificates);
    PKIXParameters parameters =
        new PKIXParameters(Set.of(new TrustAnchor(trustedRoot, null)));
    parameters.setRevocationEnabled(false);
    CertPathValidator.getInstance("PKIX").validate(certificatePath, parameters);
  }
}
