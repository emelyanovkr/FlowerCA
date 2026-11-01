package com.fidd.flowerca.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.query.CertificateRow;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;

// Syntax/type check only; no SQL execution, JDBC connection, or replacement integration database.
// Real MySQL query behavior remains the responsibility of Testcontainers integration tests.
class CertificateMetadataQueryTests {

  @Test
  void hibernateParsesActualRepositoryQueriesWithScalarDtoAndTypedParameters() throws Exception {
    var configuration = new Configuration()
        .addAnnotatedClass(CertificateEntity.class)
        .addAnnotatedClass(UserProfileEntity.class)
        .addAnnotatedClass(CaIssuerEntity.class)
        .setProperty("hibernate.dialect", "org.hibernate.dialect.MySQLDialect")
        .setProperty("hibernate.boot.allow_jdbc_metadata_access", "false")
        .setProperty("hibernate.hbm2ddl.auto", "none");
    var pageAnnotation = CertificateRepository.class.getMethod("findMetadataPage",
        UUID.class, CertificateProfile.class, String.class, Instant.class, Pageable.class)
        .getAnnotation(Query.class);
    var detailAnnotation = CertificateRepository.class.getMethod("findMetadataById", UUID.class)
        .getAnnotation(Query.class);
    try (var factory = configuration.buildSessionFactory(); var session = factory.openSession()) {
      var pageQuery = session.createQuery(pageAnnotation.value(), CertificateRow.class);
      assertThat(pageQuery.getParameter("ownerId").getParameterType()).isEqualTo(UUID.class);
      assertThat(pageQuery.getParameter("profile").getParameterType()).isEqualTo(CertificateProfile.class);
      assertThat(pageQuery.getParameter("now").getParameterType()).isEqualTo(Instant.class);
      assertThat(pageQuery.getParameter("effectiveStatus").getParameterType()).isEqualTo(String.class);
      var countQuery = session.createQuery(pageAnnotation.countQuery(), Long.class);
      assertThat(countQuery.getParameters()).hasSize(4);
      var detailQuery = session.createQuery(detailAnnotation.value(), CertificateRow.class);
      assertThat(detailQuery.getParameter("id").getParameterType()).isEqualTo(UUID.class);
    }
  }
}
