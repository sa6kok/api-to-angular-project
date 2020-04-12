package com.localbandb.localbandb.web.api.models;

import javax.validation.constraints.NotEmpty;

import static com.localbandb.localbandb.web.api.constants.Constants.*;

public class UserLoginModel {

  @NotEmpty(message = SHOULD_NOT_BE_EMPTY)
  private String username;

  @NotEmpty(message = SHOULD_NOT_BE_EMPTY)
  private String password;

  public UserLoginModel() {
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
