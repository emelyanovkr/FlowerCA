package com.fidd.flowerca.api;

import jakarta.validation.constraints.NotBlank;

public record IssueCertificateRequest(@NotBlank(message = "csr must not be blank") String csr) {}
