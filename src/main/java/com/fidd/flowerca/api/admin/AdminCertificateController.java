package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.security.ClientCertificatePrincipal;
import com.fidd.flowerca.service.admin.AdminCertificateRenewal;
import com.fidd.flowerca.service.admin.AdminCertificateService;
import com.fidd.flowerca.service.admin.CertificatePage;
import com.fidd.flowerca.service.admin.CertificateView;
import com.fidd.flowerca.persistence.model.CertificateEffectiveStatus;
import com.fidd.flowerca.persistence.model.CertificateProfile;
import com.fidd.flowerca.service.admin.RenewAdminCertificateCommand;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/certificates")
@ConditionalOnProperty(prefix = "flowerca.issuer", name = "enabled",
    havingValue = "true", matchIfMissing = true)
public class AdminCertificateController {

  private final AdminCertificateService certificates;

  public AdminCertificateController(AdminCertificateService certificates) {
    this.certificates = certificates;
  }

  @GetMapping
  public CertificatePage list(
      @RequestParam(required = false) UUID ownerId,
      @RequestParam(required = false) CertificateProfile profile,
      @RequestParam(required = false) CertificateEffectiveStatus effectiveStatus,
      @PageableDefault(size = 50, sort = "createdAt", direction = Sort.Direction.DESC)
      Pageable pageable) {
    return certificates.list(ownerId, profile, effectiveStatus, pageable);
  }

  @GetMapping("/{id}")
  public CertificateView get(@PathVariable UUID id) {
    return certificates.get(id);
  }

  @PostMapping("/renew")
  public AdminCertificateRenewal renew(
      @Valid @RequestBody RenewAdminCertificateRequest request,
      @AuthenticationPrincipal ClientCertificatePrincipal actor) {
    return certificates.renew(new RenewAdminCertificateCommand(request.csrPem()), actor);
  }

}
