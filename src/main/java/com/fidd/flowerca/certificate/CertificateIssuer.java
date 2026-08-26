package com.fidd.flowerca.certificate;

import com.fidd.flowerca.csr.ParsedCsr;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
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

  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

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

  public IssuedCertificate issue(ParsedCsr csr) {
    policy.validate(csr);

    try {
      Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
      Date notBefore = Date.from(now.minus(CLOCK_SKEW));
      Date notAfter = Date.from(now.plus(CERTIFICATE_LIFETIME));
      BigInteger serialNumber = generateSerialNumber();

      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              issuerIdentity.certificate(),
              serialNumber,
              notBefore,
              notAfter,
              csr.subject(),
              csr.publicKey());

      addLeafExtensions(builder, csr);

      ContentSigner signer =
          new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
              .build(issuerIdentity.privateKey());
      X509CertificateHolder holder = builder.build(signer);
      X509Certificate certificate =
          new JcaX509CertificateConverter().getCertificate(holder);

      certificate.verify(issuerIdentity.certificate().getPublicKey());
      certificate.checkValidity(Date.from(now));
      return new IssuedCertificate(certificate, issuerIdentity.chain());
    } catch (Exception exception) {
      throw new CertificateIssuanceException("Unable to issue certificate", exception);
    }
  }

  private void addLeafExtensions(JcaX509v3CertificateBuilder builder, ParsedCsr csr)
      throws Exception {
    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    builder.addExtension(
        Extension.extendedKeyUsage,
        false,
        new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    builder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        extensionUtils.createSubjectKeyIdentifier(csr.publicKey()));
    builder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        extensionUtils.createAuthorityKeyIdentifier(issuerIdentity.certificate()));

    GeneralName[] names =
        csr.dnsSubjectAlternativeNames().stream()
            .map(name -> new GeneralName(GeneralName.dNSName, name))
            .toArray(GeneralName[]::new);
    builder.addExtension(
        Extension.subjectAlternativeName, false, new GeneralNames(names));
  }

  private BigInteger generateSerialNumber() {
    // RFC 5280 limits certificate serial numbers to 20 octets and requires a positive value.
    return new BigInteger(159, secureRandom).setBit(158);
  }
}
