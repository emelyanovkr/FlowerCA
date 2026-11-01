package com.fidd.flowerca.api;

import com.fidd.flowerca.api.admin.UserAlreadyExistsException;
import com.fidd.flowerca.policy.CertificatePolicyException;
import com.fidd.flowerca.csr.CsrParsingException;
import com.fidd.flowerca.service.admin.CertificateNotFoundException;
import com.fidd.flowerca.service.admin.InvalidCertificateQueryException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(ApiExceptionHandler.class);

  @ExceptionHandler(UserAlreadyExistsException.class)
  public ResponseEntity<Map<String, String>> duplicateUser() {
    return error(HttpStatus.CONFLICT, "USER_ALREADY_EXISTS", "User already exists");
  }

  @ExceptionHandler({CertificatePolicyException.class, CsrParsingException.class,
      InvalidCertificateQueryException.class})
  public ResponseEntity<Map<String, String>> invalidRequest() {
    return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Request is invalid");
  }

  @ExceptionHandler(CertificateNotFoundException.class)
  public ResponseEntity<Map<String, String>> certificateNotFound() {
    return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Resource not found");
  }

  @Override
  protected ResponseEntity<Object> handleExceptionInternal(
      Exception exception, Object body, HttpHeaders headers, HttpStatusCode status,
      WebRequest request) {
    Map<String, String> safeBody = switch (status.value()) {
      case 400 -> Map.of("code", "INVALID_REQUEST", "message", "Request is invalid");
      case 404 -> Map.of("code", "NOT_FOUND", "message", "Resource not found");
      case 405 -> Map.of("code", "METHOD_NOT_ALLOWED", "message", "Method not allowed");
      case 406 -> Map.of("code", "NOT_ACCEPTABLE", "message", "Response type is not acceptable");
      case 415 -> Map.of("code", "UNSUPPORTED_MEDIA_TYPE", "message", "Media type is not supported");
      default -> Map.of("code", "REQUEST_FAILED", "message", "Request could not be completed");
    };
    return super.handleExceptionInternal(exception, safeBody, headers, status, request);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<Map<String, String>> forbidden() {
    return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied");
  }

  @ExceptionHandler({DataAccessResourceFailureException.class,
      TransientDataAccessResourceException.class, CannotCreateTransactionException.class})
  public ResponseEntity<Map<String, String>> unavailable() {
    LOGGER.warn("Administrative API database is unavailable");
    return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Service temporarily unavailable");
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
