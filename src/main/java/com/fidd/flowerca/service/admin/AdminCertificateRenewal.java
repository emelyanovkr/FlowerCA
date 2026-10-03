package com.fidd.flowerca.service.admin;

import java.time.Instant;
import java.util.UUID;

public record AdminCertificateRenewal(
    UUID certificateId, Instant notBefore, Instant notAfter, String certificateChainPem) {}
