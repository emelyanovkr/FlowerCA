package com.fidd.flowerca.issuer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(IssuerProperties.class)
public class IssuerConfiguration {

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
