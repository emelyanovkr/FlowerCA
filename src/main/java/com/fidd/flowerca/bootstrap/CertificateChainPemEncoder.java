package com.fidd.flowerca.bootstrap;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class CertificateChainPemEncoder {

  public byte[] encode(List<X509Certificate> certificates) {
    StringWriter output = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(output)) {
      for (X509Certificate certificate : certificates) {
        writer.writeObject(certificate);
      }
    } catch (IOException exception) {
      throw new AdminBootstrapException("Unable to encode admin certificate chain", exception);
    }
    return output.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  }
}
