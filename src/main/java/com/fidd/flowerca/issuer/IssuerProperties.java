package com.fidd.flowerca.issuer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties("flowerca.issuer")
public class IssuerProperties {

  private boolean enabled = true;
  private Resource keyStore;
  private String alias;
  private String password;
  private Resource trustedRoot;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public Resource getKeyStore() {
    return keyStore;
  }

  public void setKeyStore(Resource keyStore) {
    this.keyStore = keyStore;
  }

  public String getAlias() {
    return alias;
  }

  public void setAlias(String alias) {
    this.alias = alias;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public Resource getTrustedRoot() {
    return trustedRoot;
  }

  public void setTrustedRoot(Resource trustedRoot) {
    this.trustedRoot = trustedRoot;
  }
}
