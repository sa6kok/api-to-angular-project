package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.config.authentication.AuthenticationFacade;
import com.localbandb.localbandb.data.models.Reservation;
import com.localbandb.localbandb.data.models.Role;
import com.localbandb.localbandb.data.models.User;
import com.localbandb.localbandb.data.repositories.UserRepository;
import com.localbandb.localbandb.services.models.UserServiceModel;
import com.localbandb.localbandb.services.services.RoleService;
import com.localbandb.localbandb.services.services.UserService;
import com.localbandb.localbandb.web.api.models.UserRegisterModel;
import com.localbandb.localbandb.web.api.models.UserViewModel;
import javassist.NotFoundException;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;


@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleService roleService;
    private final AuthenticationFacade facade;
    private final ModelMapper modelMapper;
    private final BCryptPasswordEncoder encoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleService roleService, AuthenticationFacade facade, ModelMapper modelMapper, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.roleService = roleService;
        this.facade = facade;
        this.modelMapper = modelMapper;
        this.encoder = encoder;
    }

    @Override
   // @PreAuthorize("permitAll")
    public boolean saveUser(UserRegisterModel userRegisterModel) {

        UserServiceModel userServiceModel = modelMapper.map(userRegisterModel, UserServiceModel.class);
        userServiceModel.setRole(userRegisterModel.getRole().toUpperCase());
        if (!userServiceModel.getPassword().equals(userServiceModel.getConfirmPassword())) {
            return false;
        }
        try {
            userServiceModel.setPassword(encoder.encode(userServiceModel.getPassword()));
            User guest = modelMapper.map(userServiceModel, User.class);
            Set<Role> rolesToSave = new HashSet<>();

            if (userRepository.count() == 0) {
                rolesToSave = roleService.findAll();
            } else {
                switch (userServiceModel.getRole()) {
                    case "GUEST":
                        guest.setReservations(new ArrayList<>());
                        Role toSaveGuest = roleService.findByAuthority("ROLE_GUEST");
                        rolesToSave.add(toSaveGuest);
                        break;
                    case "HOST":
                        guest.setProperties(new ArrayList<>());
                        Role toSave = roleService.findByAuthority("ROLE_HOST");
                        rolesToSave.add(toSave);
                        break;
                }

                guest.setPayments(new ArrayList<>());
            }
            guest.setAuthorities(rolesToSave);
            userRepository.saveAndFlush(guest);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public User findByUsername(String username) throws NotFoundException {
        return userRepository.findByUsername(username).orElseThrow(() -> new NotFoundException("Username not found!"));
    }


    @Override
    public boolean checkIfUserExist(String username) {
        Optional<User> byUsername = userRepository.findByUsername(username);
        return byUsername.isPresent();
    }

    @Override
    public boolean checkIfUserWithEmailExist(String email) {
        Optional<User> byUsername = userRepository.findUserByEmail(email);
        return byUsername.isPresent();
    }

    @Override
   // @Secured("ROLE_GUEST")
    public void addUserToReservation(Reservation reservation) throws NotFoundException {
         String username = facade.getAuthentication().getName();
        User user = this.findByUsername(username);
        reservation.setGuest(user);
    }

    @Override
    public User findById(String id) throws NotFoundException {
        User user = userRepository.findById(id).orElseThrow(() -> new NotFoundException("Username not found!"));
        return user;
    }

    @Override
    @Secured("ROLE_ADMIN")
    public List<UserViewModel> findAllUsersWithoutTheLoggedIn() {
        String username = this.facade.getAuthentication().getName();
        return userRepository.findAllByUsernameNot(username).stream()
                .map(u -> {
                    UserViewModel userViewModel = modelMapper.map(u, UserViewModel.class);
                    List<String> roles = u.getAuthorities().stream().map(Role::getAuthority).collect(Collectors.toList());
                    if (u.isEnabled()) {
                        userViewModel.setActive(true);
                    }
                    userViewModel.setRoles(roles);
                    return userViewModel;
                }).collect(Collectors.toList());
    }

    @Override
    @Secured("ROLE_ADMIN")
    public boolean changeUserStatus(String id) {

        try {
            User user = userRepository.findById(id).orElseThrow(() -> new NotFoundException("User not found"));
            if (user.isEnabled()) {
                user.setEnabled(false);
            } else if (!user.isEnabled()) {
                user.setEnabled(true);
            }
            userRepository.saveAndFlush(user);
            return true;
        } catch (Exception ex) {
            return false;
        }

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository
                .findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found!"));
    }
}
