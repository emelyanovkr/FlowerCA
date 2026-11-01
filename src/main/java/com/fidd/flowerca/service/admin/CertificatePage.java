package com.fidd.flowerca.service.admin;

import java.util.List;

public record CertificatePage(
    List<CertificateView> content, int page, int size, long totalElements, int totalPages) {
  public CertificatePage {
    content = List.copyOf(content);
  }
}
