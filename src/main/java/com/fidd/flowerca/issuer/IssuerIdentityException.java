package com.fidd.flowerca.issuer;

public class IssuerIdentityException extends RuntimeException {

  public IssuerIdentityException(String message) {
    super(message);
  }

  public IssuerIdentityException(String message, Throwable cause) {
    super(message, cause);
  }
}
