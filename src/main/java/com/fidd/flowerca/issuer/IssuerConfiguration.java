package com.fidd.flowerca.issuer;

import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import com.fidd.flowerca.certificate.CertificateLifetimeProperties;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({IssuerProperties.class, CertificateLifetimeProperties.class})
public class IssuerConfiguration {

  @Bean
  CertificateChainPemEncoder certificateChainPemEncoder() {
    return new CertificateChainPemEncoder();
  }

  @Bean
  @ConditionalOnProperty(prefix = "flowerca.issuer", name = "enabled",
      havingValue = "true", matchIfMissing = true)
  CertificateIssuer certificateIssuer(
      IssuerIdentity issuerIdentity, InternalCertificatePolicy policy,
      CertificateLifetimeProperties lifetimes) {
    return new CertificateIssuer(issuerIdentity, policy, lifetimes);
  }

  @Bean
  @ConditionalOnProperty(
      prefix = "flowerca.issuer",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  IssuerIdentity issuerIdentity(IssuerProperties properties) {
    return new Pkcs12IssuerIdentityLoader().load(properties);
  }
}
