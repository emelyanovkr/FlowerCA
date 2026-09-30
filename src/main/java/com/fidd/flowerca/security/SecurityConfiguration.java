package com.fidd.flowerca.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

  @Bean
  ClientCertificateAuthenticationFilter clientCertificateAuthenticationFilter(
      ClientCertificateAuthenticationService authenticationService) {
    return new ClientCertificateAuthenticationFilter(authenticationService);
  }

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      ClientCertificateAuthenticationFilter clientCertificateAuthenticationFilter)
      throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .requestCache(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            requests ->
                requests
                    .requestMatchers("/api/v1/public/**")
                    .permitAll()
                    .requestMatchers("/api/v1/admin/**")
                    .hasAuthority("ADMIN")
                    .anyRequest()
                    .denyAll())
        .exceptionHandling(
            exceptions ->
                exceptions
                    .authenticationEntryPoint(
                        (request, response, exception) ->
                            writeError(
                                response,
                                HttpServletResponse.SC_UNAUTHORIZED,
                                "UNAUTHORIZED",
                                "Authentication required"))
                    .accessDeniedHandler(
                        (request, response, exception) ->
                            writeError(
                                response,
                                HttpServletResponse.SC_FORBIDDEN,
                                "FORBIDDEN",
                                "Access denied")))
        .addFilterBefore(
            clientCertificateAuthenticationFilter, AnonymousAuthenticationFilter.class);
    return http.build();
  }

  private void writeError(
      HttpServletResponse response, int status, String code, String message)
      throws java.io.IOException {
    response.setStatus(status);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(
        "{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}");
  }
}
