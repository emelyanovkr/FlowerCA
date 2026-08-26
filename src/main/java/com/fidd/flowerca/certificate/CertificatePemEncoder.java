package com.fidd.flowerca.certificate;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Component;

@Component
public class CertificatePemEncoder {

  public String encode(X509Certificate certificate) {
    try {
      StringWriter output = new StringWriter();
      try (JcaPEMWriter writer = new JcaPEMWriter(output)) {
        writer.writeObject(certificate);
      }
      return output.toString();
    } catch (IOException exception) {
      throw new CertificateIssuanceException("Unable to encode certificate as PEM", exception);
    }
  }
}
