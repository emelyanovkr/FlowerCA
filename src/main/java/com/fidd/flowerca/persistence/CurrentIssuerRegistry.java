package com.fidd.flowerca.persistence;

import com.fidd.flowerca.issuer.IssuerIdentity;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.repository.CaIssuerRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

@Component
public class CurrentIssuerRegistry {

  private final CaIssuerRepository repository;
  private final CaIssuerEntityFactory factory;

  public CurrentIssuerRegistry(CaIssuerRepository repository, CaIssuerEntityFactory factory) {
    this.repository = repository;
    this.factory = factory;
  }

  public CaIssuerEntity register(IssuerIdentity identity) {
    CaIssuerEntity candidate = factory.create(identity);
    return repository.findByFingerprintSha256(candidate.getFingerprintSha256()).orElseGet(
        () -> saveOrReadConcurrentRegistration(candidate));
  }

  public CaIssuerEntity requireRegistered(IssuerIdentity identity) {
    CaIssuerEntity candidate = factory.create(identity);
    return repository
        .findByFingerprintSha256(candidate.getFingerprintSha256())
        .orElseThrow(
            () -> new CertificatePersistenceException("Configured CA issuer is not registered"));
  }

  private CaIssuerEntity saveOrReadConcurrentRegistration(CaIssuerEntity candidate) {
    try {
      return repository.saveAndFlush(candidate);
    } catch (DataIntegrityViolationException exception) {
      return repository
          .findByFingerprintSha256(candidate.getFingerprintSha256())
          .orElseThrow(
              () ->
                  new CertificatePersistenceException(
                      "Unable to register configured CA issuer", exception));
    }
  }
}
