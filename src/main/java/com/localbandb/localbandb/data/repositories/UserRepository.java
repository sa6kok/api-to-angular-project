package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

  Optional<User> findByUsername(String username);

  Optional<User> findUserByEmail(String email);

  List<User> findAllByUsernameNot(String username);
}
