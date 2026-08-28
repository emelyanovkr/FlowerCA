package com.fidd.flowerca.api;

import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.certificate.CertificatePemEncoder;
import com.fidd.flowerca.certificate.IssuedCertificate;
import jakarta.validation.Valid;
import java.security.cert.X509Certificate;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/certificates")
@ConditionalOnProperty(
    prefix = "flowerca.issuer",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class CertificateController {

  private final CertificateIssuanceService issuanceService;
  private final CertificatePemEncoder pemEncoder;

  public CertificateController(
      CertificateIssuanceService issuanceService, CertificatePemEncoder pemEncoder) {
    this.issuanceService = issuanceService;
    this.pemEncoder = pemEncoder;
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public IssueCertificateResponse issue(@Valid @RequestBody IssueCertificateRequest request) {
    IssuedCertificate issued = issuanceService.issue(request.csr());
    X509Certificate certificate = issued.certificate();
    List<String> issuerChain = issued.issuerChain().stream().map(pemEncoder::encode).toList();

    return new IssueCertificateResponse(
        certificate.getSerialNumber().toString(16),
        certificate.getSubjectX500Principal().getName(),
        certificate.getIssuerX500Principal().getName(),
        certificate.getNotBefore().toInstant(),
        certificate.getNotAfter().toInstant(),
        pemEncoder.encode(certificate),
        issuerChain);
  }
}
