package com.fidd.flowerca.certificate;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class CertificateLifetimePropertiesTests {

  @Test
  void invalidLifetimePreventsConfigurationStartup() {
    new ApplicationContextRunner().withUserConfiguration(PropertiesConfiguration.class)
        .withPropertyValues("flowerca.certificates.lifetime.admin-client=0s")
        .run(context -> assertThat(context).hasFailed());
  }

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties(CertificateLifetimeProperties.class)
  static class PropertiesConfiguration {}
}
