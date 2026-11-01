package com.fidd.flowerca.api.admin;

import static org.assertj.core.api.Assertions.*;

import com.fidd.flowerca.persistence.model.CertificateEffectiveStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.service.admin.InvalidCertificateQueryException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.core.MethodParameter;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import com.fidd.flowerca.service.admin.AdminCertificateService;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

class CertificatePageableResolverTests {

  private final CertificateWebConfiguration.StrictCertificatePageableResolver resolver =
      new CertificateWebConfiguration.StrictCertificatePageableResolver();

  @Test
  void issuerDisabledDoesNotExposeSeparateReadMode() {
    new ApplicationContextRunner()
        .withPropertyValues("flowerca.issuer.enabled=false")
        .withUserConfiguration(AdminCertificateController.class, AdminCertificateService.class)
        .run(context -> assertThat(context).hasNotFailed()
            .doesNotHaveBean(AdminCertificateController.class)
            .doesNotHaveBean(AdminCertificateService.class));
  }

  @Test
  void resolvesControllerDefaultsAndStandardRepeatedSortParameters() throws Exception {
    var request = new MockHttpServletRequest();
    assertThat(resolver.supportsParameter(parameter())).isTrue();
    var defaults = resolve(request);
    assertThat(defaults.getPageNumber()).isZero();
    assertThat(defaults.getPageSize()).isEqualTo(50);
    assertThat(defaults.getSort().toList()).containsExactly(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
    request.addParameter("page", "2");
    request.addParameter("size", "20");
    request.addParameter("sort", "notAfter,asc", "createdAt,desc");
    var explicit = resolve(request);
    assertThat(explicit.getOffset()).isEqualTo(40);
    assertThat(explicit.getSort().toList()).containsExactly(
        Sort.Order.asc("notAfter"), Sort.Order.desc("createdAt"), Sort.Order.asc("id"));
  }

  @ParameterizedTest
  @CsvSource({"page,-1", "page,no", "page,2147483648", "size,0", "size,-1", "size,101",
      "size,no", "sort,certificateDer", "sort,owner.email", "sort,'createdAt,up'",
      "sort,'createdAt,asc,id'", "sort,'id;drop table certificates,asc'"})
  void rejectsInvalidInputInsteadOfFallingBack(String name, String value) throws Exception {
    var request = new MockHttpServletRequest();
    request.addParameter(name, value);
    assertThatThrownBy(() -> resolve(request)).isInstanceOf(InvalidCertificateQueryException.class);
  }

  @Test
  void rejectsDuplicateNumericParametersAndExcessiveOffset() throws Exception {
    var duplicate = new MockHttpServletRequest();
    duplicate.addParameter("size", "10", "20");
    assertThatThrownBy(() -> resolve(duplicate)).isInstanceOf(InvalidCertificateQueryException.class);
    var hugeOffset = new MockHttpServletRequest();
    hugeOffset.addParameter("page", "2147483647");
    hugeOffset.addParameter("size", "100");
    assertThatThrownBy(() -> resolve(hugeOffset)).isInstanceOf(InvalidCertificateQueryException.class);
  }

  private Pageable resolve(MockHttpServletRequest request) throws Exception {
    return resolver.resolveArgument(parameter(), null, new ServletWebRequest(request), null);
  }

  private MethodParameter parameter() throws Exception {
    return new MethodParameter(AdminCertificateController.class.getMethod("list", UUID.class,
        CertificateProfile.class, CertificateEffectiveStatus.class, Pageable.class), 3);
  }
}
