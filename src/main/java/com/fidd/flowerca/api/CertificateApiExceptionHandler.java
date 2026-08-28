package com.fidd.flowerca.api;

import com.fidd.flowerca.certificate.CertificateIssuanceException;
import com.fidd.flowerca.csr.CsrParsingException;
import com.fidd.flowerca.policy.CertificatePolicyException;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CertificateApiExceptionHandler {

  @ExceptionHandler(CsrParsingException.class)
  ResponseEntity<ApiError> handleInvalidCsr(CsrParsingException exception) {
    return ResponseEntity.badRequest().body(new ApiError("INVALID_CSR", exception.getMessage()));
  }

  @ExceptionHandler(CertificatePolicyException.class)
  ResponseEntity<ApiError> handlePolicyRejection(CertificatePolicyException exception) {
    return ResponseEntity.badRequest()
        .body(new ApiError("POLICY_REJECTED", exception.getMessage()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ResponseEntity<ApiError> handleInvalidRequest(MethodArgumentNotValidException exception) {
    String message =
        exception.getBindingResult().getFieldErrors().stream()
            .findFirst()
            .map(DefaultMessageSourceResolvable::getDefaultMessage)
            .orElse("Request is invalid");
    return ResponseEntity.badRequest().body(new ApiError("INVALID_REQUEST", message));
  }

  @ExceptionHandler(CertificateIssuanceException.class)
  ResponseEntity<ApiError> handleIssuanceFailure(CertificateIssuanceException exception) {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(new ApiError("ISSUANCE_FAILED", exception.getMessage()));
  }
}
