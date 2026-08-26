package com.fidd.flowerca.csr;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Component;

@Component
public class CsrParser {

  // todo: админ может создать сертификта с новым профилем пользователя, привязать к существующему профилю
  // саморегистрация пользователей через ACME или rest api
  // rest api эндпоинт для админа реализации crud операций с mtls
  // rest api для пользователей
  // ocsp модуль для проверки сертификатов
  // acme для клиентских сертификатов
  public ParsedCsr parse(String pem) {
    if (pem == null || pem.isBlank()) {
      throw new CsrParsingException("CSR must not be blank");
    }

    try {
      PKCS10CertificationRequest request = readPem(pem);
      PublicKey publicKey = new JcaPKCS10CertificationRequest(request).getPublicKey();
      verifySignature(request, publicKey);

      X500Principal subject = new X500Principal(request.getSubject().getEncoded());
      List<String> dnsNames = extractDnsSubjectAlternativeNames(request);
      return new ParsedCsr(subject, publicKey, publicKey.getAlgorithm(), dnsNames);
    } catch (CsrParsingException exception) {
      throw exception;
    } catch (GeneralSecurityException
        | IOException
        | OperatorCreationException
        | PKCSException
        | IllegalArgumentException exception) {
      throw new CsrParsingException("Unable to parse CSR", exception);
    }
  }

  private PKCS10CertificationRequest readPem(String pem) throws IOException {
    try (PEMParser parser = new PEMParser(new StringReader(pem))) {
      Object object = parser.readObject();
      if (!(object instanceof PKCS10CertificationRequest request)) {
        throw new CsrParsingException("PEM does not contain a PKCS#10 CSR");
      }
      if (parser.readObject() != null) {
        throw new CsrParsingException("PEM must contain exactly one PKCS#10 CSR");
      }
      return request;
    }
  }

  private void verifySignature(PKCS10CertificationRequest request, PublicKey publicKey)
      throws OperatorCreationException, PKCSException {
    boolean valid =
        request.isSignatureValid(
            new JcaContentVerifierProviderBuilder().build(publicKey));
    if (!valid) {
      throw new CsrParsingException("CSR signature is invalid");
    }
  }

  private List<String> extractDnsSubjectAlternativeNames(PKCS10CertificationRequest request) {
    var attributes = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
    if (attributes.length == 0) {
      return List.of();
    }
    if (attributes.length > 1 || attributes[0].getAttrValues().size() != 1) {
      throw new CsrParsingException("CSR contains an invalid extension request");
    }

    ASN1Encodable extensionValue = attributes[0].getAttrValues().getObjectAt(0);
    Extensions extensions = Extensions.getInstance(extensionValue);
    Extension subjectAlternativeName = extensions.getExtension(Extension.subjectAlternativeName);
    if (subjectAlternativeName == null) {
      return List.of();
    }

    GeneralNames generalNames =
        GeneralNames.getInstance(subjectAlternativeName.getParsedValue());
    List<String> dnsNames = new ArrayList<>();
    for (GeneralName generalName : generalNames.getNames()) {
      if (generalName.getTagNo() == GeneralName.dNSName) {
        dnsNames.add(generalName.getName().toString());
      }
    }
    return List.copyOf(dnsNames);
  }
}
