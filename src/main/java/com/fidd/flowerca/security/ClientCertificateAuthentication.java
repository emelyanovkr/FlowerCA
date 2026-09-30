package com.fidd.flowerca.security;

public record ClientCertificateAuthentication(
    ClientCertificatePrincipal principal, boolean administrator) {}
