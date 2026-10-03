package com.fidd.flowerca.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class ClientCertificateAuthenticationFilter extends OncePerRequestFilter {

  public static final String CERTIFICATE_ATTRIBUTE =
      "jakarta.servlet.request.X509Certificate";
  private static final Logger LOGGER =
      LoggerFactory.getLogger(ClientCertificateAuthenticationFilter.class);

  private final ClientCertificateAuthenticationService authenticationService;

  public ClientCertificateAuthenticationFilter(
      ClientCertificateAuthenticationService authenticationService) {
    this.authenticationService = authenticationService;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI().substring(request.getContextPath().length());
    // Public protocols must not depend on the certificate registry being available.
    return path.equals("/api/v1/public") || path.startsWith("/api/v1/public/");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain)
      throws ServletException, IOException {
    if (SecurityContextHolder.getContext().getAuthentication() == null) {
      X509Certificate certificate = leafCertificate(request);
      if (certificate != null) {
        try {
          authenticationService.authenticate(certificate).ifPresent(this::authenticate);
        } catch (DataAccessResourceFailureException | TransientDataAccessResourceException
            | CannotCreateTransactionException exception) {
          LOGGER.warn("Client certificate database is unavailable");
          SecurityErrorResponse.write(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
              "SERVICE_UNAVAILABLE", "Service temporarily unavailable");
          return;
        } catch (RuntimeException exception) {
          LOGGER.error("Client certificate authentication failed unexpectedly", exception);
          SecurityErrorResponse.write(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
              "INTERNAL_ERROR", "Request could not be completed");
          return;
        }
      }
    }
    filterChain.doFilter(request, response);
  }

  private X509Certificate leafCertificate(HttpServletRequest request) {
    Object attribute = request.getAttribute(CERTIFICATE_ATTRIBUTE);
    if (attribute instanceof X509Certificate[] chain && chain.length > 0) {
      return chain[0];
    }
    return null;
  }

  private void authenticate(ClientCertificateAuthentication result) {
    List<SimpleGrantedAuthority> authorities =
        result.administrator()
            ? List.of(new SimpleGrantedAuthority("ADMIN"))
            : List.of();
    UsernamePasswordAuthenticationToken authentication =
        UsernamePasswordAuthenticationToken.authenticated(
            result.principal(), null, authorities);
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }
}
