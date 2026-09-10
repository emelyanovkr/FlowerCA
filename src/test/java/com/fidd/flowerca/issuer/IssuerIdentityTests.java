package com.fidd.flowerca.issuer;

import static org.assertj.core.api.Assertions.assertThat;

import com.fidd.flowerca.testsupport.TestPki;
import org.junit.jupiter.api.Test;

class IssuerIdentityTests {

  @Test
  void doesNotExposePrivateKeyInToString() throws Exception {
    IssuerIdentity identity = TestPki.create().issuerIdentity();

    assertThat(identity.toString())
        .contains("IssuerIdentity[subject=")
        .contains("chainSize=")
        .doesNotContain("privateKey")
        .doesNotContain(identity.privateKey().toString());
  }
}
