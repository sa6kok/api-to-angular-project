package com.localbandb.localbandb.web.api.models;


import javax.validation.constraints.Min;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import static com.localbandb.localbandb.web.api.constants.Constants.*;

public class UserRegisterModel {
  private final String REGEX_USERNAME = "^[a-zA-Z1-9]+$";
  private final String REGEX_EMAIL = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

  @Size(min = 6, max = 25, message = SHOULD_BE_BETWEEN_3_25_SYMBOLS)
  @Pattern(regexp = REGEX_USERNAME, message = NOT_VALID_USE_ONLY_LETTERS_OR_NUMBERS)
  private String username;

  @Size(min = 6, message = SHOULD_BE_AT_LEAST_SYMBOLS)
  private String password;

  @Size(min = 6, message = SHOULD_BE_AT_LEAST_SYMBOLS)
  private String confirmPassword;

  @Pattern(regexp = REGEX_EMAIL, message = IS_NOT_VALID)
  private String email;

  @Size(min = 2, max = 15, message = SHOULD_BE_BETWEEN_2_15_SYMBOLS)
  private String firstName;

  @Size(min = 2, max = 15, message = SHOULD_BE_BETWEEN_2_15_SYMBOLS)
  private String lastName;

  @Min(value = 18, message = SHOULD_BE_AT_LEAST_18)
  private Integer age;

  private String role;

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }

  public UserRegisterModel() {
  }

  public String getUsername() {
    if(username == null) {
      return null;
    }
    return username.toLowerCase();
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public void setLastName(String lastName) {
    this.lastName = lastName;
  }

  public Integer getAge() {
    return age;
  }

  public void setAge(Integer age) {
    this.age = age;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getConfirmPassword() {
    return confirmPassword;
  }

  public void setConfirmPassword(String confirmPassword) {
    this.confirmPassword = confirmPassword;
  }
}
