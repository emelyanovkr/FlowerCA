package com.fidd.flowerca.api.admin;

import com.fidd.flowerca.persistence.entity.AuditEventEntity;
import com.fidd.flowerca.persistence.entity.UserProfileEntity;
import com.fidd.flowerca.persistence.model.AuditAction;
import com.fidd.flowerca.persistence.model.AuditResult;
import com.fidd.flowerca.persistence.model.AuditTargetType;
import com.fidd.flowerca.persistence.model.UserRole;
import com.fidd.flowerca.persistence.repository.AuditEventRepository;
import com.fidd.flowerca.persistence.repository.UserProfileRepository;
import com.fidd.flowerca.policy.InternalCertificatePolicy;
import com.fidd.flowerca.security.ClientCertificatePrincipal;
import java.util.Locale;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminUserService {

  private final UserProfileRepository users;
  private final AuditEventRepository auditEvents;
  private final InternalCertificatePolicy identityPolicy;

  public AdminUserService(
      UserProfileRepository users,
      AuditEventRepository auditEvents,
      InternalCertificatePolicy identityPolicy) {
    this.users = users;
    this.auditEvents = auditEvents;
    this.identityPolicy = identityPolicy;
  }

  @Transactional
  public UserProfileEntity createUser(
      CreateUserRequest request, ClientCertificatePrincipal actor) {
    String displayName = request.displayName().trim();
    String email = request.email().trim().toLowerCase(Locale.ROOT);
    identityPolicy.validateUserProfile(displayName, email);
    if (users.findByEmailIgnoreCase(email).isPresent()) {
      throw new UserAlreadyExistsException();
    }

    UserProfileEntity user;
    try {
      user = users.saveAndFlush(new UserProfileEntity(displayName, email, UserRole.USER));
    } catch (DataIntegrityViolationException exception) {
      throw new UserAlreadyExistsException();
    }
    auditEvents.save(
        new AuditEventEntity(
            actor.profileId(),
            actor.certificateId(),
            actor.certificateFingerprintSha256(),
            AuditAction.USER_CREATED,
            AuditTargetType.USER_PROFILE,
            user.getId(),
            AuditResult.SUCCESS,
            null));
    return user;
  }
}
