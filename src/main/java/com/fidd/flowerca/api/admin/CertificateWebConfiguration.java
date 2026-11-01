package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.service.admin.CertificatePagination;
import com.fidd.flowerca.service.admin.InvalidCertificateQueryException;
import java.util.List;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CertificateWebConfiguration implements WebMvcConfigurer {

  @Override
  public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
    resolvers.add(new StrictCertificatePageableResolver());
  }

  // Preserve safe 400 errors instead of Spring's fallback/clamping for bad page/size values.
  static class StrictCertificatePageableResolver extends PageableHandlerMethodArgumentResolver {
    StrictCertificatePageableResolver() {
      setMaxPageSize(CertificatePagination.MAX_PAGE_SIZE);
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
      return parameter.getDeclaringClass() == AdminCertificateController.class
          && super.supportsParameter(parameter);
    }

    @Override
    public Pageable resolveArgument(MethodParameter parameter, ModelAndViewContainer container,
        NativeWebRequest request, WebDataBinderFactory binderFactory) {
      validateNumber(request, "page", 0, Integer.MAX_VALUE);
      validateNumber(request, "size", 1, CertificatePagination.MAX_PAGE_SIZE);
      return CertificatePagination.validate(super.resolveArgument(parameter, container, request, binderFactory));
    }

    private void validateNumber(NativeWebRequest request, String name, int min, int max) {
      String[] values = request.getParameterValues(name);
      if (values == null) {
        return;
      }
      if (values.length != 1) {
        throw new InvalidCertificateQueryException();
      }
      if (values[0].isBlank()) {
        return;
      }
      try {
        int value = Integer.parseInt(values[0].trim());
        if (value < min || value > max) {
          throw new InvalidCertificateQueryException();
        }
      } catch (NumberFormatException exception) {
        throw new InvalidCertificateQueryException();
      }
    }
  }
}
