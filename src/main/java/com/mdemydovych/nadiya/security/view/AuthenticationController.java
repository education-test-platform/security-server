package com.mdemydovych.nadiya.security.view;

import com.mdemydovych.nadiya.model.user.UserRole;
import com.mdemydovych.nadiya.security.model.UserDto;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthenticationController {

  @GetMapping("/login")
  public String login(Model model) {
    return "LoginPage";
  }

  @GetMapping("/registration")
  public String registration(Model model) {
    model.addAttribute("user", new UserDto());
    model.addAttribute("roles", UserRole.values());
    return "RegistrationPage";
  }

}
