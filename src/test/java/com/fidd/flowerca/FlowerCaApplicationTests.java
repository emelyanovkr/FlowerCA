package com.fidd.flowerca;

import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest(properties = "flowerca.issuer.enabled=false")
@Import(MySqlTestcontainerConfiguration.class)
class FlowerCaApplicationTests {

  @Test
  void contextLoads() {}
}
