package com.fidd.flowerca.bootstrap;

import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.CurrentIssuerRegistry;
import com.fidd.flowerca.persistence.repository.AdminBootstrapStateRepository;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.service.CertificateIssuanceService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AdminBootstrapProperties.class)
public class AdminBootstrapConfiguration {

  @Bean
  @ConditionalOnProperty(
      prefix = "flowerca.issuer",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  FirstAdminBootstrapService firstAdminBootstrapService(
      AdminBootstrapStateRepository bootstrapStates,
      UserProfileRepository userProfiles,
      CertificateRepository certificates,
      AuditEventRepository auditEvents,
      CurrentIssuerRegistry issuerRegistry,
      CertificateIssuanceService issuanceService,
      CsrParser csrParser,
      IssuerIdentity issuerIdentity) {
    return new FirstAdminBootstrapService(
        bootstrapStates,
        userProfiles,
        certificates,
        auditEvents,
        issuerRegistry,
        issuanceService,
        csrParser,
        issuerIdentity);
  }

  @Bean
  CertificateChainPemEncoder certificateChainPemEncoder() {
    return new CertificateChainPemEncoder();
  }

  @Bean
  @ConditionalOnProperty(
      prefix = "flowerca.bootstrap.admin",
      name = "enabled",
      havingValue = "true")
  FirstAdminBootstrapRunner firstAdminBootstrapRunner(
      AdminBootstrapProperties properties,
      FirstAdminBootstrapService bootstrapService,
      CertificateChainPemEncoder pemEncoder) {
    return new FirstAdminBootstrapRunner(properties, bootstrapService, pemEncoder);
  }
}
