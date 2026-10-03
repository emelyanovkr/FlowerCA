package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.security.ClientCertificatePrincipal;
import com.fidd.flowerca.service.admin.AdminCertificateRenewal;
import com.fidd.flowerca.service.admin.AdminCertificateRenewalUseCase;
import com.fidd.flowerca.service.admin.RenewAdminCertificateCommand;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/certificates")
@ConditionalOnProperty(prefix = "flowerca.issuer", name = "enabled",
    havingValue = "true", matchIfMissing = true)
public class AdminCertificateController {

  private final AdminCertificateRenewalUseCase renewal;

  public AdminCertificateController(AdminCertificateRenewalUseCase renewal) {
    this.renewal = renewal;
  }

  @PostMapping("/renew")
  public AdminCertificateRenewal renew(
      @Valid @RequestBody RenewAdminCertificateRequest request,
      @AuthenticationPrincipal ClientCertificatePrincipal actor) {
    return renewal.renew(new RenewAdminCertificateCommand(request.csrPem()), actor);
  }

}
