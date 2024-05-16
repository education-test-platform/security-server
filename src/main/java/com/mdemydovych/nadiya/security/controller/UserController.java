package com.mdemydovych.nadiya.security.controller;

import com.mdemydovych.nadiya.security.model.UserDto;
import com.mdemydovych.nadiya.security.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

  private final UserService userService;

  @PostMapping("/save")
  public void save(@RequestBody UserDto userDto) {
    userService.save(userDto);
  }
}
