package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.security.ClientCertificatePrincipal;
import jakarta.validation.Valid;
import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// todo: hashicorp vault open source analogue
//  discovery service

@RestController
@RequestMapping("/api/v1/admin/users")
public class AdminUserController {

  private final AdminUserService users;

  public AdminUserController(AdminUserService users) {
    this.users = users;
  }

  @PostMapping
  public ResponseEntity<UserResponse> create(
      @Valid @RequestBody CreateUserRequest request,
      @AuthenticationPrincipal ClientCertificatePrincipal actor) {
    UserProfileEntity user = users.createUser(request, actor);
    return ResponseEntity.created(URI.create("/api/v1/admin/users/" + user.getId()))
        .body(UserResponse.from(user));
  }
}
