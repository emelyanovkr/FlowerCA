package com.fidd.flowerca.api;

import com.fidd.flowerca.api.admin.UserAlreadyExistsException;
import com.fidd.flowerca.policy.CertificatePolicyException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(ApiExceptionHandler.class);

  @ExceptionHandler(UserAlreadyExistsException.class)
  public ResponseEntity<Map<String, String>> duplicateUser() {
    return error(HttpStatus.CONFLICT, "USER_ALREADY_EXISTS", "User already exists");
  }

  @ExceptionHandler({
    MethodArgumentNotValidException.class,
    HttpMessageNotReadableException.class,
    CertificatePolicyException.class
  })
  public ResponseEntity<Map<String, String>> invalidRequest() {
    return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Request is invalid");
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<Map<String, String>> internalError(Exception exception) {
    LOGGER.error("Administrative API request failed", exception);
    return error(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Request could not be completed");
  }

  private ResponseEntity<Map<String, String>> error(
      HttpStatus status, String code, String message) {
    return ResponseEntity.status(status).body(Map.of("code", code, "message", message));
  }
}
