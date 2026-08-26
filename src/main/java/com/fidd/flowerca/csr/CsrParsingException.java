package com.fidd.flowerca.csr;

public class CsrParsingException extends RuntimeException {

  public CsrParsingException(String message) {
    super(message);
  }

  public CsrParsingException(String message, Throwable cause) {
    super(message, cause);
  }
}
