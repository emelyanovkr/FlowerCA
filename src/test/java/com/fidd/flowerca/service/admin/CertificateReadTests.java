package com.fidd.flowerca.service.admin;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fidd.flowerca.persistence.model.CertificateEffectiveStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.persistence.model.CertificateStatus;
import com.fidd.flowerca.persistence.repository.CertificateRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.certificate.CertificateChainPemEncoder;
import com.fidd.flowerca.service.CertificateIssuanceService;
import com.fidd.flowerca.persistence.query.CertificateRow;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Pageable;

class CertificateReadTests {

  private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");

  @Test
  void sortingHasUniqueTieBreakerAndIdSortDoesNotDuplicateIt() {
    var pageable = CertificatePagination.validate(PageRequest.of(2, 50, Sort.by(Sort.Direction.DESC, "createdAt")));
    assertThat(pageable.getOffset()).isEqualTo(100);
    assertThat(pageable.getSort().toList()).containsExactly(
        Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
    assertThat(CertificatePagination.validate(PageRequest.of(0, 1, Sort.by("id")))
        .getSort().toList()).containsExactly(Sort.Order.asc("id"));
  }

  @ParameterizedTest
  @CsvSource({"-1,50", "0,0", "0,-1", "0,101", "2147483647,100"})
  void rejectsInvalidPagination(int page, int size) {
    var invalid = mock(Pageable.class);
    when(invalid.isPaged()).thenReturn(true);
    when(invalid.getPageNumber()).thenReturn(page);
    when(invalid.getPageSize()).thenReturn(size);
    when(invalid.getOffset()).thenReturn((long) page * size);
    assertThatThrownBy(() -> CertificatePagination.validate(invalid))
        .isInstanceOf(InvalidCertificateQueryException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"owner.email", "certificateDer", "unknown", "id;drop table certificates"})
  void rejectsUnapprovedSort(String sort) {
    assertThatThrownBy(() -> CertificatePagination.validate(PageRequest.of(0, 50, Sort.by(sort))))
        .isInstanceOf(InvalidCertificateQueryException.class);
  }

  @Test
  void validatesNullOrUnpagedInputAndIdentifier() {
    var service = service(mock(CertificateRepository.class));
    assertThatThrownBy(() -> CertificatePagination.validate(Pageable.unpaged()))
        .isInstanceOf(InvalidCertificateQueryException.class);
    assertThatThrownBy(() -> service.list(null, null, null, null)).isInstanceOf(InvalidCertificateQueryException.class);
    assertThatThrownBy(() -> service.get(null)).isInstanceOf(InvalidCertificateQueryException.class);
  }

  @Test
  void defaultAndMultipleSortOrdersRemainBoundedAndDeterministic() {
    assertThat(CertificatePagination.validate(PageRequest.of(0, 100)).getSort().toList())
        .containsExactly(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
    var sort = Sort.by(Sort.Order.asc("notAfter"), Sort.Order.desc("createdAt"));
    assertThat(CertificatePagination.validate(PageRequest.of(0, 50, sort)).getSort().toList())
        .containsExactly(Sort.Order.asc("notAfter"), Sort.Order.desc("createdAt"), Sort.Order.asc("id"));
    assertThatThrownBy(() -> CertificatePagination.validate(PageRequest.of(0, 50,
        Sort.by(Sort.Order.asc("id").ignoreCase())))).isInstanceOf(InvalidCertificateQueryException.class);
    assertThatThrownBy(() -> CertificatePagination.validate(PageRequest.of(0, 50,
        Sort.by(Sort.Order.asc("id").nullsFirst())))).isInstanceOf(InvalidCertificateQueryException.class);
    assertThatThrownBy(() -> CertificatePagination.validate(PageRequest.of(0, 50,
        Sort.by("id", "id", "id", "id", "id")))).isInstanceOf(InvalidCertificateQueryException.class);
  }

  @Test
  void effectiveStatusHonorsHalfOpenValidityAndStoredTerminalStates() {
    assertThat(CertificateEffectiveStatus.at(CertificateStatus.ACTIVE, NOW, NOW.plusSeconds(1), NOW))
        .isEqualTo(CertificateEffectiveStatus.ACTIVE);
    assertThat(CertificateEffectiveStatus.at(CertificateStatus.ACTIVE, NOW.minusSeconds(1), NOW, NOW))
        .isEqualTo(CertificateEffectiveStatus.EXPIRED);
    assertThat(CertificateEffectiveStatus.at(CertificateStatus.ACTIVE, NOW.plusSeconds(1), NOW.plusSeconds(2), NOW))
        .isEqualTo(CertificateEffectiveStatus.NOT_YET_VALID);
    assertThat(CertificateEffectiveStatus.at(CertificateStatus.REVOKED, NOW.minusSeconds(2), NOW.minusSeconds(1), NOW))
        .isEqualTo(CertificateEffectiveStatus.REVOKED);
    assertThat(CertificateEffectiveStatus.at(CertificateStatus.EXPIRED, NOW.minusSeconds(1), NOW.plusSeconds(1), NOW))
        .isEqualTo(CertificateEffectiveStatus.EXPIRED);
  }

  @Test
  void viewEncodesUnsignedSerialFingerprintAndNullableOwner() {
    var row = row(null);
    var view = CertificateView.from(row, NOW);
    assertThat(view.serialNumberHex()).isEqualTo("80ff");
    assertThat(view.fingerprintSha256Hex()).isEqualTo("ab".repeat(32));
    assertThat(view.owner()).isNull();
    assertThat(view.issuer().id()).isEqualTo(row.issuerId());
    assertThat(view.storedStatus()).isEqualTo(CertificateStatus.ACTIVE);
    assertThat(view.effectiveStatus()).isEqualTo(CertificateEffectiveStatus.ACTIVE);
    var ownerRow = row(UUID.randomUUID());
    assertThat(CertificateView.from(ownerRow, NOW).owner())
        .isEqualTo(new CertificateView.Owner(ownerRow.ownerId(), "Alice", "alice@example.internal"));
  }

  @Test
  void serviceMapsPageAndMissingDetailWithoutLoadingEntities() {
    var repository = mock(CertificateRepository.class);
    var service = service(repository);
    var row = row(UUID.randomUUID());
    var pageable = PageRequest.of(0, 50, Sort.by("id"));
    when(repository.findMetadataPage(eq(row.ownerId()), eq(CertificateProfile.USER_CLIENT), isNull(),
        any(Instant.class), eq(pageable)))
        .thenReturn(new PageImpl<>(List.of(row), PageRequest.of(0, 50), 1));
    var page = service.list(row.ownerId(), CertificateProfile.USER_CLIENT, null, pageable);
    assertThat(page.totalElements()).isEqualTo(1);
    assertThat(page.totalPages()).isEqualTo(1);
    assertThat(page.page()).isZero();
    assertThat(page.size()).isEqualTo(50);
    assertThat(page.content()).extracting(CertificateView::id).containsExactly(row.id());
    assertThatThrownBy(() -> page.content().clear()).isInstanceOf(UnsupportedOperationException.class);
    when(repository.findMetadataById(row.id())).thenReturn(Optional.of(row));
    assertThat(service.get(row.id()).id()).isEqualTo(row.id());
    UUID missing = UUID.randomUUID();
    when(repository.findMetadataById(missing)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> service.get(missing)).isInstanceOf(CertificateNotFoundException.class);
  }

  private AdminCertificateService service(CertificateRepository repository) {
    return new AdminCertificateService(mock(UserProfileRepository.class), repository,
        mock(CertificateIssuanceService.class), mock(AuditEventRepository.class),
        mock(CertificateChainPemEncoder.class));
  }

  private CertificateRow row(UUID ownerId) {
    byte[] fingerprint = new byte[32];
    java.util.Arrays.fill(fingerprint, (byte) 0xab);
    return new CertificateRow(UUID.randomUUID(), ownerId, "Alice", "alice@example.internal",
        UUID.randomUUID(), "CN=Intermediate", new byte[] {(byte) 0x80, (byte) 0xff}, fingerprint,
        CertificateProfile.USER_CLIENT, CertificateStatus.ACTIVE, "CN=Alice", NOW.minusSeconds(1),
        NOW.plusSeconds(1), null, null, NOW.minusSeconds(1));
  }
}
