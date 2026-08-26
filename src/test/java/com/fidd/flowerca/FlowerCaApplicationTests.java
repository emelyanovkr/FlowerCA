package com.fidd.flowerca;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "flowerca.issuer.enabled=false")
class FlowerCaApplicationTests {

  @Test
  void contextLoads() {}
}
