package com.fidd.flowerca.bootstrap;

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("flowerca.bootstrap.admin")
public class AdminBootstrapProperties {

  private boolean enabled;
  private String displayName;
  private String email;
  private Path csrPath;
  private Path certificateChainOutput;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public Path getCsrPath() {
    return csrPath;
  }

  public void setCsrPath(Path csrPath) {
    this.csrPath = csrPath;
  }

  public Path getCertificateChainOutput() {
    return certificateChainOutput;
  }

  public void setCertificateChainOutput(Path certificateChainOutput) {
    this.certificateChainOutput = certificateChainOutput;
  }
}
