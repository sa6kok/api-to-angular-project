package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.data.models.Reservation;
import com.localbandb.localbandb.data.models.User;
import com.localbandb.localbandb.web.api.models.UserRegisterModel;
import com.localbandb.localbandb.web.api.models.UserViewModel;
import javassist.NotFoundException;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface UserService extends UserDetailsService {

  boolean saveUser(UserRegisterModel userRegisterModel);

  User findByUsername(String username) throws NotFoundException;

  boolean checkIfUserExist(String username);

  boolean checkIfUserWithEmailExist(String email);

    void addUserToReservation(Reservation reservation) throws NotFoundException;

  User findById(String id) throws NotFoundException;

  List<UserViewModel> findAllUsersWithoutTheLoggedIn();

  boolean changeUserStatus(String id) throws NotFoundException;
}
