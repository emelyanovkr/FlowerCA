package com.fidd.flowerca.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import jakarta.servlet.FilterChain;
import java.security.cert.X509Certificate;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class ClientCertificateAuthenticationFilterTests {

  private final ClientCertificateAuthenticationService service =
      mock(ClientCertificateAuthenticationService.class);
  private final ClientCertificateAuthenticationFilter filter =
      new ClientCertificateAuthenticationFilter(service);
  private final X509Certificate certificate = mock(X509Certificate.class);
  private final FilterChain chain = mock(FilterChain.class);

  @AfterEach
  void clearSecurity() { SecurityContextHolder.clearContext(); }

  @Test
  void databaseOutageStopsAdminRequestWithConstant503() throws Exception {
    when(service.authenticate(certificate))
        .thenThrow(new DataAccessResourceFailureException("internal database address"));
    var response = run("/api/v1/admin/users");
    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getContentAsString()).isEqualTo(
        "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Service temporarily unavailable\"}");
    verifyNoInteractions(chain);
  }

  @Test
  void unexpectedFailureIsNotDisguisedAsMissingCredentials() throws Exception {
    when(service.authenticate(certificate)).thenThrow(new IllegalStateException("internal error"));
    var response = run("/api/v1/admin/users");
    assertThat(response.getStatus()).isEqualTo(500);
    assertThat(response.getContentAsString()).contains("INTERNAL_ERROR").doesNotContain("internal error");
    verifyNoInteractions(chain);
  }

  @Test
  void unknownCertificateContinuesWithoutAuthentication() throws Exception {
    when(service.authenticate(certificate)).thenReturn(Optional.empty());
    run("/api/v1/admin/users");
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(chain).doFilter(any(), any());
  }

  @Test
  void publicRequestWithCertificateDoesNotUseDatabase() throws Exception {
    run("/api/v1/public/probe");
    verifyNoInteractions(service);
    verify(chain).doFilter(any(), any());
  }

  private MockHttpServletResponse run(String path) throws Exception {
    var request = new MockHttpServletRequest("POST", path);
    request.setAttribute(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] {certificate});
    var response = new MockHttpServletResponse();
    filter.doFilter(request, response, chain);
    return response;
  }
}
