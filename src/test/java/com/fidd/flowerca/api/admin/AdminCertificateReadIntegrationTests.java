package com.fidd.flowerca.api.admin;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fidd.flowerca.certificate.CertificateIdentity;
import com.fidd.flowerca.certificate.CertificateIssuer;
import com.fidd.flowerca.csr.CsrParser;
import com.fidd.flowerca.persistence.CertificateEntityFactory;
import com.fidd.flowerca.persistence.entity.CaIssuerEntity;
import com.fidd.flowerca.persistence.entity.CertificateEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.*;
import com.fidd.flowerca.persistence.repository.*;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.security.ClientCertificateAuthenticationFilter;
import com.fidd.flowerca.security.ClientCertificatePrincipal;
import com.fidd.flowerca.service.admin.*;
import com.fidd.flowerca.testsupport.CertificateReadSqlInspector;
import com.fidd.flowerca.testsupport.MySqlTestcontainerConfiguration;
import com.fidd.flowerca.testsupport.TestPki;
import com.fidd.flowerca.testsupport.TlsTestMaterial;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.ObjectMapper;

// Docker required. Production controller/service/issuer/security wiring; only external dev PKI supplied.
// Certificate fixtures are inserted directly to isolate read checks from issuance/audit mutations.
// MockMvc checks HTTP authorization, not a TLS handshake (covered by the existing TLS 1.3 suite).
@SpringBootTest(properties = {
    "flowerca.issuer.enabled=true",
    "spring.jpa.properties.hibernate.session_factory.statement_inspector=com.fidd.flowerca.testsupport.CertificateReadSqlInspector"})
@AutoConfigureMockMvc
@Import(MySqlTestcontainerConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AdminCertificateReadIntegrationTests {

  private static final String ROUTE = "/api/v1/admin/certificates";
  @Autowired private MockMvc mvc;
  @Autowired private ObjectMapper json;
  @Autowired private UserProfileRepository users;
  @Autowired private CertificateRepository certificates;
  @Autowired private CaIssuerRepository issuers;
  @Autowired private AuditEventRepository audit;
  @Autowired private AdminCertificateService service;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private ApplicationContext context;

  private TestPki pki;
  private CertificateIssuer fixtureIssuer;
  private CaIssuerEntity issuer;
  private UserProfileEntity admin;
  private CertificateEntity adminRecord;
  private X509Certificate adminCertificate;
  private static TlsTestMaterial material;

  @DynamicPropertySource
  static void issuerMaterial(DynamicPropertyRegistry properties) throws Exception {
    material = TlsTestMaterial.create();
    properties.add("flowerca.issuer.key-store", () -> material.path("issuer.p12").toUri().toString());
    properties.add("flowerca.issuer.alias", () -> "test-issuer");
    properties.add("flowerca.issuer.password", material::password);
    properties.add("flowerca.issuer.trusted-root", () -> material.path("root.pem").toUri().toString());
    properties.add("spring.security.user.password", material::password);
  }

  @AfterAll
  static void removeMaterial() throws Exception {
    if (material != null) {
      material.close();
    }
  }

  @BeforeAll
  void prepareIssuer() throws Exception {
    pki = material.pki();
    fixtureIssuer = new CertificateIssuer(pki.issuerIdentity(), new InternalCertificatePolicy());
    issuer = issuers.findByFingerprintSha256(java.security.MessageDigest.getInstance("SHA-256")
        .digest(pki.issuerIdentity().certificate().getEncoded())).orElseThrow();
  }

  @BeforeEach
  void prepareAdmin() throws Exception {
    admin = user(UserRole.ADMIN);
    var issued = fixtureIssuer.issue(new CsrParser().parse(pki.createCsrPem("untrusted.internal")),
        CertificateProfile.ADMIN_CLIENT,
        new CertificateIdentity.User(admin.getId(), admin.getDisplayName(), admin.getEmail()));
    adminCertificate = issued.certificate();
    adminRecord = certificates.saveAndFlush(new CertificateEntityFactory().create(
        admin, issuer, CertificateProfile.ADMIN_CLIENT, adminCertificate));
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void bothReadsRequireCertificateAndUserIsForbidden() throws Exception {
    var ordinary = user(UserRole.USER);
    var issued = fixtureIssuer.issue(new CsrParser().parse(pki.createCsrPem("untrusted.internal")),
        CertificateProfile.USER_CLIENT,
        new CertificateIdentity.User(ordinary.getId(), ordinary.getDisplayName(), ordinary.getEmail()));
    certificates.saveAndFlush(new CertificateEntityFactory().create(
        ordinary, issuer, CertificateProfile.USER_CLIENT, issued.certificate()));
    for (String path : List.of(ROUTE, ROUTE + "/" + adminRecord.getId())) {
      mvc.perform(get(path)).andExpect(status().isUnauthorized())
          .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
      mvc.perform(get(path).requestAttr(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
          new X509Certificate[] {issued.certificate()})).andExpect(status().isForbidden())
          .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }
  }

  @Test
  void adminReadsMetadataWithUnifiedProductionWiringWithoutMutation() throws Exception {
    long certificatesBefore = certificates.count();
    long profilesBefore = users.count();
    long auditBefore = audit.count();
    assertThat(context.getBeansOfType(com.fidd.flowerca.service.CertificateIssuanceService.class)).hasSize(1);
    assertThat(context.getBean(AdminCertificateController.class)).isNotNull();
    mvc.perform(adminGet(ROUTE).param("ownerId", admin.getId().toString()))
        .andExpect(status().isOk()).andExpect(jsonPath("$.page").value(0))
        .andExpect(jsonPath("$.size").value(50)).andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].id").value(adminRecord.getId().toString()))
        .andExpect(jsonPath("$.content[0].owner.email").value(admin.getEmail()))
        .andExpect(jsonPath("$.content[0].profile").value("ADMIN_CLIENT"))
        .andExpect(jsonPath("$.content[0].certificateDer").doesNotExist());
    mvc.perform(adminGet(ROUTE + "/" + adminRecord.getId()))
        .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(adminRecord.getId().toString()))
        .andExpect(jsonPath("$.owner.id").value(admin.getId().toString()))
        .andExpect(jsonPath("$.issuer.id").value(issuer.getId().toString()))
        .andExpect(jsonPath("$.issuer.subjectDn").value(issuer.getSubjectDn()))
        .andExpect(jsonPath("$.serialNumberHex").value(adminCertificate.getSerialNumber().toString(16)))
        .andExpect(jsonPath("$.fingerprintSha256Hex").value(java.util.HexFormat.of().formatHex(adminRecord.getFingerprintSha256())))
        .andExpect(jsonPath("$.notBefore").exists()).andExpect(jsonPath("$.notAfter").exists())
        .andExpect(jsonPath("$.storedStatus").value("ACTIVE"))
        .andExpect(jsonPath("$.effectiveStatus").value("ACTIVE"))
        .andExpect(jsonPath("$.certificateDer").doesNotExist())
        .andExpect(jsonPath("$.certificateChainPem").doesNotExist());
    assertThat(certificates.count()).isEqualTo(certificatesBefore);
    assertThat(users.count()).isEqualTo(profilesBefore);
    assertThat(audit.count()).isEqualTo(auditBefore);
    assertThat(certificates.findById(adminRecord.getId()).orElseThrow().getCertificateDer())
        .isEqualTo(adminRecord.getCertificateDer());
  }

  @Test
  void paginationAndTiedSortAreStableAcrossPages() throws Exception {
    var owner = user(UserRole.USER);
    var ids = List.of(fixture(owner, CertificateProfile.USER_CLIENT).getId(),
        fixture(owner, CertificateProfile.USER_CLIENT).getId(),
        fixture(owner, CertificateProfile.USER_CLIENT).getId());
    Instant created = Instant.now().minusSeconds(100).truncatedTo(ChronoUnit.MICROS);
    jdbc.update("update certificates set created_at=? where user_profile_id=UUID_TO_BIN(?)",
        Timestamp.from(created), owner.getId().toString());
    var expected = ids.stream().map(UUID::toString).sorted().toList();
    var first = mvc.perform(adminGet(ROUTE).param("ownerId", owner.getId().toString())
        .param("size", "2").param("sort", "createdAt,asc"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(3))
        .andExpect(jsonPath("$.totalPages").value(2)).andExpect(jsonPath("$.content.length()").value(2))
        .andReturn().getResponse().getContentAsString();
    assertThat(json.readTree(first).get("content").get(0).get("id").asText()).isEqualTo(expected.get(0));
    assertThat(json.readTree(first).get("content").get(1).get("id").asText()).isEqualTo(expected.get(1));
    mvc.perform(adminGet(ROUTE).param("ownerId", owner.getId().toString()).param("page", "1")
        .param("size", "2").param("sort", "createdAt,asc"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.content.length()").value(1))
        .andExpect(jsonPath("$.content[0].id").value(expected.get(2)));
    mvc.perform(adminGet(ROUTE).param("ownerId", owner.getId().toString()).param("page", "2").param("size", "2"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.content").isEmpty())
        .andExpect(jsonPath("$.totalElements").value(3));
  }

  @Test
  void profileAndOwnerFiltersAndEmptyPageWork() throws Exception {
    var other = fixture(admin, CertificateProfile.USER_CLIENT);
    mvc.perform(adminGet(ROUTE).param("ownerId", admin.getId().toString()).param("profile", "USER_CLIENT"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].id").value(other.getId().toString()));
    mvc.perform(adminGet(ROUTE).param("ownerId", UUID.randomUUID().toString()))
        .andExpect(status().isOk()).andExpect(jsonPath("$.content").isEmpty())
        .andExpect(jsonPath("$.totalElements").value(0)).andExpect(jsonPath("$.totalPages").value(0));
  }

  @Test
  void effectiveStatusFiltersAndCardAgreeWithoutUpdatingStaleActive() throws Exception {
    var owner = user(UserRole.USER);
    var expired = fixture(owner, CertificateProfile.USER_CLIENT);
    var future = fixture(owner, CertificateProfile.USER_CLIENT);
    var revoked = fixture(owner, CertificateProfile.USER_CLIENT);
    Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
    dates(expired, now.minusSeconds(200), now.minusSeconds(100));
    dates(future, now.plusSeconds(100), now.plusSeconds(200));
    dates(revoked, now.minusSeconds(200), now.minusSeconds(100));
    jdbc.update("update certificates set status='REVOKED',revoked_at=?,revocation_reason='KEY_COMPROMISE' where id=UUID_TO_BIN(?)",
        Timestamp.from(now.minusSeconds(150)), revoked.getId().toString());
    for (var entry : java.util.Map.of("EXPIRED", expired, "NOT_YET_VALID", future, "REVOKED", revoked).entrySet()) {
      mvc.perform(adminGet(ROUTE).param("ownerId", owner.getId().toString()).param("effectiveStatus", entry.getKey()))
          .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1))
          .andExpect(jsonPath("$.content[0].id").value(entry.getValue().getId().toString()))
          .andExpect(jsonPath("$.content[0].effectiveStatus").value(entry.getKey()));
      mvc.perform(adminGet(ROUTE + "/" + entry.getValue().getId()))
          .andExpect(status().isOk()).andExpect(jsonPath("$.effectiveStatus").value(entry.getKey()));
    }
    mvc.perform(adminGet(ROUTE).param("ownerId", owner.getId().toString()).param("effectiveStatus", "ACTIVE"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(0));
    mvc.perform(adminGet(ROUTE + "/" + revoked.getId()))
        .andExpect(jsonPath("$.revocationReason").value("KEY_COMPROMISE"))
        .andExpect(jsonPath("$.revokedAt").exists());
    assertThat(certificates.findById(expired.getId()).orElseThrow().getStatus()).isEqualTo(CertificateStatus.ACTIVE);
  }

  @Test
  void databaseFiltersHonorExactValidityBoundariesAndStoredExpired() throws Exception {
    var owner = user(UserRole.USER);
    Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
    var starting = fixture(owner, CertificateProfile.USER_CLIENT);
    var ending = fixture(owner, CertificateProfile.USER_CLIENT);
    var storedExpired = fixture(owner, CertificateProfile.USER_CLIENT);
    dates(starting, now, now.plusSeconds(100));
    dates(ending, now.minusSeconds(100), now);
    dates(storedExpired, now.minusSeconds(100), now.plusSeconds(100));
    jdbc.update("update certificates set status='EXPIRED' where id=UUID_TO_BIN(?)", storedExpired.getId().toString());
    var pageable = PageRequest.of(0, 50, Sort.by("id"));
    assertThat(certificates.findMetadataPage(owner.getId(), null, "ACTIVE", now, pageable).getContent())
        .extracting(com.fidd.flowerca.persistence.query.CertificateRow::id).containsExactly(starting.getId());
    var expiredPage = certificates.findMetadataPage(owner.getId(), null, "EXPIRED", now, pageable);
    assertThat(expiredPage.getTotalElements()).isEqualTo(2);
    assertThat(expiredPage.getContent()).extracting(com.fidd.flowerca.persistence.query.CertificateRow::id)
        .containsExactlyInAnyOrder(ending.getId(), storedExpired.getId());
  }

  @Test
  void serverCertificateWithoutOwnerRemainsVisible() throws Exception {
    var server = fixture(null, CertificateProfile.TLS_SERVER);
    mvc.perform(adminGet(ROUTE).param("profile", "TLS_SERVER"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].id").value(server.getId().toString()))
        .andExpect(jsonPath("$.content[0].owner").isEmpty());
    mvc.perform(adminGet(ROUTE + "/" + server.getId()))
        .andExpect(status().isOk()).andExpect(jsonPath("$.owner").isEmpty());
  }

  @ParameterizedTest
  @CsvSource({"page,-1", "page,no", "size,0", "size,101", "ownerId,invalid", "profile,UNKNOWN",
      "effectiveStatus,UNKNOWN", "sort,certificateDer", "sort,owner.email"})
  void invalidParametersReturnConstant400(String parameter, String value) throws Exception {
    mvc.perform(adminGet(ROUTE).param(parameter, value)).andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
        .andExpect(jsonPath("$.message").value("Request is invalid"));
  }

  @Test
  void invalidAndUnknownIdentifierReturnSafeErrors() throws Exception {
    mvc.perform(adminGet(ROUTE + "/invalid")).andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    mvc.perform(adminGet(ROUTE + "/" + UUID.randomUUID())).andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("NOT_FOUND"))
        .andExpect(jsonPath("$.message").value("Resource not found"));
  }

  @Test
  void directServiceCallsAlsoRequireAdminAuthority() {
    var pageable = PageRequest.of(0, 50, Sort.by("id"));
    assertThatThrownBy(() -> service.list(null, null, null, pageable)).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    assertThatThrownBy(() -> service.get(adminRecord.getId())).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    SecurityContextHolder.getContext().setAuthentication(
        UsernamePasswordAuthenticationToken.authenticated("user", null, List.of()));
    assertThatThrownBy(() -> service.list(null, null, null, pageable)).isInstanceOf(AccessDeniedException.class);
    assertThatThrownBy(() -> service.get(adminRecord.getId())).isInstanceOf(AccessDeniedException.class);
  }

  @Test
  void scalarReadsUseTwoQueriesForPageOneForDetailAndNoDer() throws Exception {
    var owner = user(UserRole.USER);
    for (int i = 0; i < 3; i++) {
      fixture(owner, CertificateProfile.USER_CLIENT);
    }
    SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
        new ClientCertificatePrincipal(adminRecord.getId(), admin.getId(), adminRecord.getFingerprintSha256()),
        null, List.of(new SimpleGrantedAuthority("ADMIN"))));
    CertificateReadSqlInspector.start();
    List<String> statements;
    CertificatePage page;
    try {
      page = service.list(owner.getId(), null, null, PageRequest.of(0, 3, Sort.by(Sort.Direction.DESC, "createdAt")));
    } finally {
      statements = CertificateReadSqlInspector.finish();
    }
    assertThat(page.content()).hasSize(3);
    assertThat(statements).hasSize(2).allSatisfy(sql -> {
      assertThat(sql.toLowerCase()).startsWith("select").doesNotContain("certificate_der");
    });
    assertThat(statements.get(0).toLowerCase()).contains("join user_profiles", "join ca_issuers");
    CertificateReadSqlInspector.start();
    CertificateView detail;
    try {
      detail = service.get(page.content().getFirst().id());
    } finally {
      statements = CertificateReadSqlInspector.finish();
    }
    assertThat(detail.owner().email()).isEqualTo(owner.getEmail());
    assertThat(statements).hasSize(1).allSatisfy(sql -> assertThat(sql).doesNotContain("certificate_der"));
  }

  private UserProfileEntity user(UserRole role) {
    return users.saveAndFlush(new UserProfileEntity("Read User", "read-" + UUID.randomUUID() + "@example.internal", role));
  }

  private CertificateEntity fixture(UserProfileEntity owner, CertificateProfile profile) throws Exception {
    CertificateIdentity identity = owner == null
        ? new CertificateIdentity.TlsServer(List.of("read.internal"))
        : new CertificateIdentity.User(owner.getId(), owner.getDisplayName(), owner.getEmail());
    var issued = fixtureIssuer.issue(new CsrParser().parse(pki.createCsrPem("untrusted.internal")), profile, identity);
    return certificates.saveAndFlush(new CertificateEntityFactory().create(owner, issuer, profile, issued.certificate()));
  }

  private void dates(CertificateEntity certificate, Instant notBefore, Instant notAfter) {
    jdbc.update("update certificates set not_before=?,not_after=? where id=UUID_TO_BIN(?)",
        Timestamp.from(notBefore), Timestamp.from(notAfter), certificate.getId().toString());
  }

  private MockHttpServletRequestBuilder adminGet(String path) {
    return get(path).requestAttr(ClientCertificateAuthenticationFilter.CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] {adminCertificate});
  }
}
