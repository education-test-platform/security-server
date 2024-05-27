package com.mdemydovych.nadiya.security.user.entity;

import com.mdemydovych.nadiya.model.user.UserRole;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import java.util.Date;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

@Getter
@Setter
@Entity(name = "users")
public class User {

  @Id
  @UuidGenerator
  private String id;

  private String username;

  private String email;

  private String password;

  @Column(name = "registration_date", updatable = false)
  private Date registrationDate;

  @Enumerated(EnumType.STRING)
  private UserRole role;
}
