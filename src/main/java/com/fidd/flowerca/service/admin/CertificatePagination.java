package com.fidd.flowerca.service.admin;

import java.util.Set;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

public final class CertificatePagination {
  public static final int MAX_PAGE_SIZE = 100;
  private static final Set<String> SORT_FIELDS = Set.of("createdAt", "notBefore", "notAfter", "id");

  private CertificatePagination() {}

  public static Pageable validate(Pageable pageable) {
    if (pageable == null || !pageable.isPaged() || pageable.getPageSize() > MAX_PAGE_SIZE
        || pageable.getPageNumber() < 0 || pageable.getPageSize() < 1
        || pageable.getOffset() > Integer.MAX_VALUE) {
      throw new InvalidCertificateQueryException();
    }
    Sort sort = pageable.getSort().isSorted() ? pageable.getSort() : Sort.by(Sort.Direction.DESC, "createdAt");
    var orders = sort.toList();
    if (orders.size() > SORT_FIELDS.size() || orders.stream().anyMatch(order ->
        !SORT_FIELDS.contains(order.getProperty()) || order.isIgnoreCase()
            || order.getNullHandling() != Sort.NullHandling.NATIVE)) {
      throw new InvalidCertificateQueryException();
    }
    if (sort.getOrderFor("id") == null) {
      sort = sort.and(Sort.by(orders.getFirst().getDirection(), "id"));
    }
    return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), sort);
  }
}
