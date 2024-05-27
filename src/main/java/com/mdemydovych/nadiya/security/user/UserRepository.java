package com.mdemydovych.nadiya.security.user;

import com.mdemydovych.nadiya.security.user.entity.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

interface UserRepository extends JpaRepository<User, String> {

  Optional<User> findByEmail(String email);

}
