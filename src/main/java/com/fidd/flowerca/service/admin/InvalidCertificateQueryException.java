package com.fidd.flowerca.service.admin;

public class InvalidCertificateQueryException extends RuntimeException {
  public InvalidCertificateQueryException() {
    super("Invalid certificate query");
  }
}
