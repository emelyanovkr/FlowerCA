package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.service.admin.RenewAdminCertificateCommand;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RenewAdminCertificateRequest(
    @NotBlank @Size(max = RenewAdminCertificateCommand.MAX_CSR_LENGTH) String csrPem) {}
