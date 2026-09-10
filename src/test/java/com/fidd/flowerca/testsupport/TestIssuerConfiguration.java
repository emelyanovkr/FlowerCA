package com.fidd.flowerca.testsupport;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.CurrentIssuerRegistry;
import com.fidd.flowerca.persistence.IssuedCertificatePersistenceService;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.service.CertificateIssuanceService;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration(proxyBeanMethods = false)
public class TestIssuerConfiguration {

  @Bean
  TestPki testPki() throws Exception {
    return TestPki.create();
  }

  @Bean
  @Primary
  IssuerIdentity testIssuerIdentity(TestPki testPki) {
    return testPki.issuerIdentity();
  }

  @Bean
  @Primary
  CertificateIssuer testCertificateIssuer(
      IssuerIdentity issuerIdentity, InternalCertificatePolicy policy) {
    return new CertificateIssuer(issuerIdentity, policy);
  }

  @Bean
  CertificateIssuanceService testCertificateIssuanceService(
      CsrParser csrParser,
      CertificateIssuer certificateIssuer,
      IssuerIdentity issuerIdentity,
      IssuedCertificatePersistenceService persistenceService) {
    return new CertificateIssuanceService(
        csrParser, certificateIssuer, issuerIdentity, persistenceService);
  }

  @Bean
  ApplicationRunner registerTestIssuer(
      CurrentIssuerRegistry issuerRegistry, IssuerIdentity issuerIdentity) {
    return arguments -> issuerRegistry.register(issuerIdentity);
  }
}
