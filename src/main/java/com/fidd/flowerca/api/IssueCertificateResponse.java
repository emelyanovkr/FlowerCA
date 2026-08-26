package com.fidd.flowerca.api;

import java.time.Instant;
import java.util.List;

public record IssueCertificateResponse(
    String serialNumber,
    String subject,
    String issuer,
    Instant notBefore,
    Instant notAfter,
    String certificate,
    List<String> issuerChain) {}
