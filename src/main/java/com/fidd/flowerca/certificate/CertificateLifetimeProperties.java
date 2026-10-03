package com.fidd.flowerca.certificate;

import com.fidd.flowerca.persistence.model.CertificateProfile;
import jakarta.validation.constraints.AssertTrue;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("flowerca.certificates.lifetime")
public class CertificateLifetimeProperties {

  private Duration tlsServer = Duration.ofDays(30);
  private Duration userClient = Duration.ofDays(30);
  private Duration adminClient = Duration.ofDays(30);

  public Duration getTlsServer() { return tlsServer; }
  public void setTlsServer(Duration value) { tlsServer = value; }
  public Duration getUserClient() { return userClient; }
  public void setUserClient(Duration value) { userClient = value; }
  public Duration getAdminClient() { return adminClient; }
  public void setAdminClient(Duration value) { adminClient = value; }

  @AssertTrue(message = "Certificate lifetimes must be positive and at most 3650 days")
  public boolean isValid() {
    return valid(tlsServer) && valid(userClient) && valid(adminClient);
  }

  public Duration forProfile(CertificateProfile profile) {
    if (!isValid()) {
      throw new IllegalArgumentException("Invalid certificate lifetime configuration");
    }
    return switch (profile) {
      case TLS_SERVER -> tlsServer;
      case USER_CLIENT -> userClient;
      case ADMIN_CLIENT -> adminClient;
    };
  }

  private boolean valid(Duration value) {
    return value != null && value.compareTo(Duration.ofSeconds(1)) >= 0
        && value.compareTo(Duration.ofDays(3650)) <= 0;
  }
}
