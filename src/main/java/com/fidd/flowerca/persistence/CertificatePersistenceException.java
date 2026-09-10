package com.fidd.flowerca.persistence;

public class CertificatePersistenceException extends RuntimeException {

  public CertificatePersistenceException(String message) {
    super(message);
  }

  public CertificatePersistenceException(String message, Throwable cause) {
    super(message, cause);
  }
}
