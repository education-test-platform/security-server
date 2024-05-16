package com.mdemydovych.nadiya.security.user;

import com.mdemydovych.nadiya.security.model.UserDto;
import com.mdemydovych.nadiya.security.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;

  private final UserMapper userMapper;

  public void save(UserDto userDto) {
    User toSave = userMapper.toEntity(userDto);
    userRepository.save(toSave);
  }

  public UserDto findUserByEmail(String email) {
    return userRepository.findByEmail(email)
        .map(userMapper::toDto)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }
}
