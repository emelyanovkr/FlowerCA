package com.fidd.flowerca.service.admin;

public class CertificateNotFoundException extends RuntimeException {
  public CertificateNotFoundException() {
    super("Certificate not found");
  }
}
