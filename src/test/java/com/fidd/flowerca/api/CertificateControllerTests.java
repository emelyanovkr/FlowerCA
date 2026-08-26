package com.fidd.flowerca.api;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fidd.flowerca.application.CertificateIssuanceService;
import com.fidd.flowerca.certificate.CertificatePemEncoder;
import com.fidd.flowerca.certificate.IssuedCertificate;
import com.fidd.flowerca.csr.CsrParsingException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CertificateControllerTests {

  private CertificateIssuanceService issuanceService;
  private CertificatePemEncoder pemEncoder;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    issuanceService = mock(CertificateIssuanceService.class);
    pemEncoder = mock(CertificatePemEncoder.class);
    CertificateController controller = new CertificateController(issuanceService, pemEncoder);
    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new CertificateApiExceptionHandler())
            .build();
  }

  @Test
  void returnsIssuedCertificateAndChain() throws Exception {
    X509Certificate leaf = certificate(
        "CN=service-a.internal", "CN=FlowerCA Intermediate CA", BigInteger.valueOf(42));
    X509Certificate intermediate = certificate(
        "CN=FlowerCA Intermediate CA", "CN=FlowerCA Root CA", BigInteger.TWO);
    X509Certificate root = certificate(
        "CN=FlowerCA Root CA", "CN=FlowerCA Root CA", BigInteger.ONE);
    when(issuanceService.issue("pem-csr"))
        .thenReturn(new IssuedCertificate(leaf, List.of(intermediate, root)));
    when(pemEncoder.encode(leaf)).thenReturn("leaf-pem");
    when(pemEncoder.encode(intermediate)).thenReturn("intermediate-pem");
    when(pemEncoder.encode(root)).thenReturn("root-pem");

    mockMvc
        .perform(
            post("/api/v1/certificates")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"csr\":\"pem-csr\"}"))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.serialNumber").value("2a"))
        .andExpect(jsonPath("$.subject").value("CN=service-a.internal"))
        .andExpect(jsonPath("$.issuer").value("CN=FlowerCA Intermediate CA"))
        .andExpect(jsonPath("$.certificate").value("leaf-pem"))
        .andExpect(jsonPath("$.issuerChain[0]").value("intermediate-pem"))
        .andExpect(jsonPath("$.issuerChain[1]").value("root-pem"));
  }

  @Test
  void returnsBadRequestForInvalidCsr() throws Exception {
    when(issuanceService.issue("invalid"))
        .thenThrow(new CsrParsingException("CSR signature is invalid"));

    mockMvc
        .perform(
            post("/api/v1/certificates")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"csr\":\"invalid\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_CSR"))
        .andExpect(jsonPath("$.message").value("CSR signature is invalid"));
  }

  @Test
  void returnsBadRequestForBlankCsr() throws Exception {
    mockMvc
        .perform(
            post("/api/v1/certificates")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"csr\":\"\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
        .andExpect(jsonPath("$.message").value("csr must not be blank"));
  }

  private X509Certificate certificate(String subject, String issuer, BigInteger serial) {
    X509Certificate certificate = mock(X509Certificate.class);
    when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
    when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal(issuer));
    when(certificate.getSerialNumber()).thenReturn(serial);
    when(certificate.getNotBefore()).thenReturn(Date.from(Instant.parse("2026-08-14T00:00:00Z")));
    when(certificate.getNotAfter()).thenReturn(Date.from(Instant.parse("2026-09-13T00:00:00Z")));
    return certificate;
  }
}
