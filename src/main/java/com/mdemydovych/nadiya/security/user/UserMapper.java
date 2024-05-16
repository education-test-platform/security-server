package com.mdemydovych.nadiya.security.user;

import com.mdemydovych.nadiya.security.model.UserDto;
import com.mdemydovych.nadiya.security.user.entity.User;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class UserMapper {

  private final PasswordEncoder passwordEncoder;

  public User toEntity(final UserDto user) {
    User userEntity = new User();
    userEntity.setUsername(user.getUsername());
    userEntity.setPassword(passwordEncoder.encode(user.getPassword()));
    userEntity.setEmail(user.getEmail());
    userEntity.setRole(user.getRole());
    userEntity.setRegistrationDate(new Date());
    userEntity.setId(user.getId());
    return userEntity;
  }

  public UserDto toDto(final User user) {
    UserDto result = new UserDto();
    result.setUsername(user.getUsername());
    result.setPassword(user.getPassword());
    result.setEmail(user.getEmail());
    result.setRole(user.getRole());
    result.setRegistrationDate(user.getRegistrationDate());
    result.setId(user.getId());
    return result;
  }
}
