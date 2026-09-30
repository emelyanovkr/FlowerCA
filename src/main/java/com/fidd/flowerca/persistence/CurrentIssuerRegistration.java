package com.fidd.flowerca.persistence;

import com.fidd.flowerca.bootstrap.AdminBootstrapProperties;
import com.fidd.flowerca.issuer.IssuerIdentity;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
    prefix = "flowerca.issuer",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class CurrentIssuerRegistration implements ApplicationRunner {

  private final CurrentIssuerRegistry registry;
  private final IssuerIdentity issuerIdentity;
  private final AdminBootstrapProperties bootstrapProperties;

  public CurrentIssuerRegistration(
      CurrentIssuerRegistry registry,
      IssuerIdentity issuerIdentity,
      AdminBootstrapProperties bootstrapProperties) {
    this.registry = registry;
    this.issuerIdentity = issuerIdentity;
    this.bootstrapProperties = bootstrapProperties;
  }

  @Override
  public void run(ApplicationArguments arguments) {
    if (!bootstrapProperties.isEnabled()) {
      registry.register(issuerIdentity);
    }
  }
}
