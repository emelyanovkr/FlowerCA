package com.fidd.flowerca.persistence;

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

  public CurrentIssuerRegistration(
      CurrentIssuerRegistry registry, IssuerIdentity issuerIdentity) {
    this.registry = registry;
    this.issuerIdentity = issuerIdentity;
  }

  @Override
  public void run(ApplicationArguments arguments) {
    registry.register(issuerIdentity);
  }
}
