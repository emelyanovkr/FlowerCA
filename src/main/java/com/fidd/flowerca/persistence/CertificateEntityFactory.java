package com.fidd.flowerca.persistence;

import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.springframework.stereotype.Component;

@Component
public class CertificateEntityFactory {

  public CertificateEntity create(
      UserProfileEntity userProfile,
      CaIssuerEntity issuer,
      CertificateProfile profile,
      X509Certificate certificate) {
    try {
      byte[] certificateDer = certificate.getEncoded();
      byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(certificateDer);

      return new CertificateEntity(
          userProfile,
          issuer,
          unsignedSerialNumber(certificate),
          fingerprint,
          profile,
          certificate.getSubjectX500Principal().getName(),
          certificateDer,
          certificate.getNotBefore().toInstant(),
          certificate.getNotAfter().toInstant());
    } catch (CertificateEncodingException | NoSuchAlgorithmException exception) {
      throw new CertificatePersistenceException(
          "Unable to prepare issued certificate for persistence", exception);
    }
  }

  private byte[] unsignedSerialNumber(X509Certificate certificate) {
    byte[] serialNumber = certificate.getSerialNumber().toByteArray();
    if (serialNumber.length > 1 && serialNumber[0] == 0) {
      return Arrays.copyOfRange(serialNumber, 1, serialNumber.length);
    }
    return serialNumber;
  }
}
