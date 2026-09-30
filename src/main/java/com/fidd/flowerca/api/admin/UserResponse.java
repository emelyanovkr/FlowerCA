package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.model.UserStatus;
import java.util.UUID;

public record UserResponse(
    UUID id,
    String displayName,
    String email,
    UserRole role,
    UserStatus status) {

  public static UserResponse from(UserProfileEntity user) {
    return new UserResponse(
        user.getId(),
        user.getDisplayName(),
        user.getEmail(),
        user.getRole(),
        user.getStatus());
  }
}
