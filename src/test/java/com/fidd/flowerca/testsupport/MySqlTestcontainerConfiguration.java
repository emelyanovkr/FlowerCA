package com.fidd.flowerca.testsupport;

import java.time.Duration;
import java.util.Map;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.mysql.MySQLContainer;

@TestConfiguration(proxyBeanMethods = false)
public class MySqlTestcontainerConfiguration {

  @Bean
  @ServiceConnection
  MySQLContainer mysqlContainer() {
    return new MySQLContainer("mysql:8.4")
        .withTmpFs(Map.of("/var/lib/mysql", "rw"))
        .withStartupTimeout(Duration.ofMinutes(5));
  }
}
