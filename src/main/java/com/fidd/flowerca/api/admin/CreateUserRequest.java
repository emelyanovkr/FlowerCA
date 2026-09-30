package com.fidd.flowerca.api.admin;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
    @NotBlank @Size(max = 64) String displayName,
    @NotBlank @Email @Size(max = 254) String email) {}
