package com.fidd.flowerca.persistence;

import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.springframework.stereotype.Component;

@Component
public class CaIssuerEntityFactory {

  public CaIssuerEntity create(IssuerIdentity identity) {
    X509Certificate certificate = identity.certificate();
    try {
      byte[] certificateDer = certificate.getEncoded();
      byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(certificateDer);
      String name = "issuer-" + HexFormat.of().formatHex(fingerprint);

      return new CaIssuerEntity(
          name,
          certificate.getSubjectX500Principal().getName(),
          unsigned(certificate.getSerialNumber().toByteArray()),
          subjectKeyIdentifier(certificate),
          fingerprint,
          certificateDer,
          certificate.getNotBefore().toInstant(),
          certificate.getNotAfter().toInstant());
    } catch (CertificateEncodingException | NoSuchAlgorithmException exception) {
      throw new CertificatePersistenceException(
          "Unable to prepare CA issuer for persistence", exception);
    }
  }

  private byte[] subjectKeyIdentifier(X509Certificate certificate)
      throws NoSuchAlgorithmException {
    byte[] encodedExtension = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    if (encodedExtension != null) {
      byte[] extensionValue = ASN1OctetString.getInstance(encodedExtension).getOctets();
      return SubjectKeyIdentifier.getInstance(extensionValue).getKeyIdentifier();
    }
    return new JcaX509ExtensionUtils()
        .createSubjectKeyIdentifier(certificate.getPublicKey())
        .getKeyIdentifier();
  }

  private byte[] unsigned(byte[] value) {
    if (value.length > 1 && value[0] == 0) {
      return Arrays.copyOfRange(value, 1, value.length);
    }
    return value;
  }
}
