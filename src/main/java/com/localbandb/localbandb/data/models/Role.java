package com.localbandb.localbandb.data.models;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
public class Role extends BaseEntity implements GrantedAuthority {

  @Column(name = "authority" , nullable = false, updatable = false)
  private String authority;

  /*@ManyToMany(targetEntity = User.class, mappedBy = "authorities")
  private Set<User> users = new HashSet<>();*/

  public Role() {
  }

  public Role(String authority) {
    this.authority = authority;
  }

  @Override
  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }

 /* public Set<User> getUsers() {
    return users;
  }

  public void setUsers(Set<User> users) {
    this.users = users;
  }*/
}
