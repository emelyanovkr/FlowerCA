package com.fidd.flowerca.csr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CsrParserTests {

  private CsrParser parser;
  private KeyPair keyPair;

  @BeforeEach
  void setUp() throws Exception {
    parser = new CsrParser();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();
  }

  @Test
  void parsesValidCsrAndExtractsDnsNames() throws Exception {
    String pem = createCsrPem("service-a.internal", "service-b.internal");

    ParsedCsr csr = parser.parse(pem);

    assertThat(csr.subject().getName()).contains("CN=service-a.internal");
    assertThat(csr.publicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    assertThat(csr.publicKeyAlgorithm()).isEqualTo("RSA");
    assertThat(csr.dnsSubjectAlternativeNames())
        .containsExactly("service-a.internal", "service-b.internal");
  }

  @Test
  void parsesValidCsrWithoutSubjectAlternativeNames() throws Exception {
    String pem = createCsrPem();

    ParsedCsr csr = parser.parse(pem);

    assertThat(csr.dnsSubjectAlternativeNames()).isEmpty();
  }

  @Test
  void rejectsCsrWithDamagedSignature() throws Exception {
    PKCS10CertificationRequest request = createCsr("service-a.internal");
    byte[] damaged = request.getEncoded();
    damaged[damaged.length - 1] ^= 0x01;
    String pem = toPem(new PKCS10CertificationRequest(damaged));

    assertThatThrownBy(() -> parser.parse(pem))
        .isInstanceOf(CsrParsingException.class)
        .hasMessage("CSR signature is invalid");
  }

  @Test
  void rejectsInvalidPem() {
    assertThatThrownBy(() -> parser.parse("not a certificate request"))
        .isInstanceOf(CsrParsingException.class)
        .hasMessage("PEM does not contain a PKCS#10 CSR");
  }

  @Test
  void rejectsBlankCsr() {
    assertThatThrownBy(() -> parser.parse("  "))
        .isInstanceOf(CsrParsingException.class)
        .hasMessage("CSR must not be blank");
  }

  private String createCsrPem(String... dnsNames) throws Exception {
    return toPem(createCsr(dnsNames));
  }

  private PKCS10CertificationRequest createCsr(String... dnsNames) throws Exception {
    X500Name subject = new X500Name("CN=service-a.internal,O=FlowerCA Development,C=RU");
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

    if (dnsNames.length > 0) {
      GeneralName[] names = new GeneralName[dnsNames.length];
      for (int index = 0; index < dnsNames.length; index++) {
        names[index] = new GeneralName(GeneralName.dNSName, dnsNames[index]);
      }

      ExtensionsGenerator extensions = new ExtensionsGenerator();
      extensions.addExtension(
          Extension.subjectAlternativeName, false, new GeneralNames(names));
      builder.addAttribute(
          PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
    }

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    return builder.build(signer);
  }

  private String toPem(PKCS10CertificationRequest request) throws Exception {
    StringWriter output = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(output)) {
      writer.writeObject(request);
    }
    return output.toString();
  }
}
