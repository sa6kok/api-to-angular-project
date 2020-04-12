package com.localbandb.localbandb.web.api.controlers;

import com.localbandb.localbandb.data.models.User;
import com.localbandb.localbandb.payload.JwtResponse;
import com.localbandb.localbandb.security.jwt.JwtUtils;
import com.localbandb.localbandb.services.services.UserService;
import com.localbandb.localbandb.web.api.models.UserLoginModel;
import com.localbandb.localbandb.web.api.models.UserRegisterModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController extends BaseController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;



    @Autowired
    public UserController(UserService userService, AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/check/username/{username}")
    public boolean checkUsername(@PathVariable String username ) {
      return userService.checkIfUserExist(username);
    }

    @GetMapping("/check/email/{email}")
    public boolean checkEmail(@PathVariable String email ) {
        return userService.checkIfUserWithEmailExist(email);
    }


    @PostMapping("/login")
    @Secured("ROLE_ANONYMOUS")
    public ResponseEntity<?> login(@RequestBody UserLoginModel model) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(model.getUsername(), model.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        User userDetails = (User) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
        } catch (Exception ex) {

           return null;
        }

    }

    @PostMapping("/register")
    @Secured("ROLE_ANONYMOUS")
    public boolean registerConfirm(@RequestBody UserRegisterModel model) {
        return userService.saveUser(model);
    }
}
