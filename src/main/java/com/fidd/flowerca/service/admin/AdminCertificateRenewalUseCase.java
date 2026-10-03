package com.fidd.flowerca.service.admin;

import com.fidd.flowerca.security.ClientCertificatePrincipal;

public interface AdminCertificateRenewalUseCase {

  AdminCertificateRenewal renew(
      RenewAdminCertificateCommand command, ClientCertificatePrincipal actor);
}
