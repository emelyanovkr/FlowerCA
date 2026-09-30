package com.fidd.flowerca.certificate;

import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnBean(IssuerIdentity.class)
public class CertificateIssuer {

  static final Duration CERTIFICATE_LIFETIME = Duration.ofDays(30);
  static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

  private final IssuerIdentity issuerIdentity;
  private final InternalCertificatePolicy policy;
  private final Clock clock;
  private final SecureRandom secureRandom;

  @Autowired
  public CertificateIssuer(
      IssuerIdentity issuerIdentity, InternalCertificatePolicy policy) {
    this(issuerIdentity, policy, Clock.systemUTC(), new SecureRandom());
  }

  CertificateIssuer(
      IssuerIdentity issuerIdentity,
      InternalCertificatePolicy policy,
      Clock clock,
      SecureRandom secureRandom) {
    this.issuerIdentity = issuerIdentity;
    this.policy = policy;
    this.clock = clock;
    this.secureRandom = secureRandom;
  }

  public IssuedCertificate issue(
      ParsedCsr csr, CertificateProfile profile, CertificateIdentity identity) {
    policy.validate(csr, profile, identity);

    try {
      Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
      Instant notBefore =
          laterOf(
              now.minus(CLOCK_SKEW),
              issuerIdentity.certificate().getNotBefore().toInstant());
      Instant notAfter =
          earlierOf(
              now.plus(CERTIFICATE_LIFETIME),
              issuerIdentity.certificate().getNotAfter().toInstant());
      if (notBefore.isAfter(now) || !notAfter.isAfter(now)) {
        throw new CertificateIssuanceException(
            "Intermediate CA validity does not allow issuing a currently valid leaf certificate");
      }
      BigInteger serialNumber = generateSerialNumber();

      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              issuerIdentity.certificate(),
              serialNumber,
              Date.from(notBefore),
              Date.from(notAfter),
              subjectFor(profile, identity),
              csr.publicKey());

      addLeafExtensions(builder, profile, identity, csr);

      ContentSigner signer =
          new JcaContentSignerBuilder(signatureAlgorithmFor(issuerIdentity.privateKey()))
              .build(issuerIdentity.privateKey());
      X509CertificateHolder holder = builder.build(signer);
      X509Certificate certificate =
          new JcaX509CertificateConverter().getCertificate(holder);

      certificate.verify(issuerIdentity.certificate().getPublicKey());
      certificate.checkValidity(Date.from(now));
      return new IssuedCertificate(certificate, issuerIdentity.chain(), profile);
    } catch (CertificateIssuanceException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new CertificateIssuanceException("Unable to issue certificate", exception);
    }
  }

  private void addLeafExtensions(
      JcaX509v3CertificateBuilder builder,
      CertificateProfile profile,
      CertificateIdentity identity,
      ParsedCsr csr)
      throws Exception {
    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(
        Extension.keyUsage,
        true,
        keyUsageFor(profile));
    builder.addExtension(
        Extension.extendedKeyUsage,
        false,
        extendedKeyUsageFor(profile));
    builder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        extensionUtils.createSubjectKeyIdentifier(csr.publicKey()));
    builder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        extensionUtils.createAuthorityKeyIdentifier(issuerIdentity.certificate()));

    builder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(subjectAlternativeNamesFor(profile, identity)));
  }

  private X500Principal subjectFor(
      CertificateProfile profile, CertificateIdentity identity)
      throws IOException {
    String commonName =
        switch (profile) {
          case TLS_SERVER ->
              ((CertificateIdentity.TlsServer) identity)
                  .dnsNames()
                  .getFirst()
                  .toLowerCase(Locale.ROOT);
          case USER_CLIENT, ADMIN_CLIENT ->
              ((CertificateIdentity.User) identity).displayName().trim();
        };
    X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE);
    subject.addRDN(BCStyle.CN, commonName);
    return new X500Principal(subject.build().getEncoded());
  }

  private KeyUsage keyUsageFor(CertificateProfile profile) {
    return switch (profile) {
      case TLS_SERVER ->
          new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
      case USER_CLIENT, ADMIN_CLIENT -> new KeyUsage(KeyUsage.digitalSignature);
    };
  }

  private ExtendedKeyUsage extendedKeyUsageFor(CertificateProfile profile) {
    return switch (profile) {
      case TLS_SERVER -> new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
      case USER_CLIENT, ADMIN_CLIENT ->
          new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
    };
  }

  private GeneralName[] subjectAlternativeNamesFor(
      CertificateProfile profile, CertificateIdentity identity) {
    return switch (profile) {
      case TLS_SERVER ->
          ((CertificateIdentity.TlsServer) identity)
              .dnsNames()
              .stream()
              .map(name -> new GeneralName(GeneralName.dNSName, name.toLowerCase(Locale.ROOT)))
              .toArray(GeneralName[]::new);
      case USER_CLIENT, ADMIN_CLIENT -> userSubjectAlternativeNames(
          (CertificateIdentity.User) identity);
    };
  }

  private GeneralName[] userSubjectAlternativeNames(
      CertificateIdentity.User identity) {
    List<GeneralName> names = new ArrayList<>();
    names.add(
        new GeneralName(
            GeneralName.uniformResourceIdentifier,
            "urn:flowerca:user:" + identity.profileId()));
    if (identity.email() != null) {
      names.add(
          new GeneralName(
              GeneralName.rfc822Name,
              identity.email().trim().toLowerCase(Locale.ROOT)));
    }
    return names.toArray(GeneralName[]::new);
  }

  private String signatureAlgorithmFor(PrivateKey privateKey) {
    return switch (privateKey.getAlgorithm()) {
      case "RSA" -> "SHA256withRSA";
      case "EC" -> "SHA256withECDSA";
      case "Ed25519" -> "Ed25519";
      case "Ed448" -> "Ed448";
      default ->
          throw new CertificateIssuanceException(
              "Unsupported Intermediate private key algorithm");
    };
  }

  private Instant laterOf(Instant first, Instant second) {
    return first.isAfter(second) ? first : second;
  }

  private Instant earlierOf(Instant first, Instant second) {
    return first.isBefore(second) ? first : second;
  }

  private BigInteger generateSerialNumber() {
    // RFC 5280 limits certificate serial numbers to 20 octets and requires a positive value.
    return new BigInteger(159, secureRandom).setBit(158);
  }
}
