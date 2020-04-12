package com.localbandb.localbandb.data.models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import org.hibernate.validator.constraints.Email;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.validation.constraints.Min;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Set;

@Entity
public class User extends BaseEntity implements UserDetails {

  @Size(min = 3, max = 25)
  @Column(name = "username", nullable = false, unique = true)
  private String username;

  @Size(min = 3, max = 25)
  @Email
  @Column(name = "email", nullable = false, unique = true)
  private String email;

  @Column(name = "password" , nullable = false)
  private String password;

  @Size(min = 3, max = 25)
  @Column(name = "first_name", nullable = false)
  private String firstName;


  @Size(min = 3, max = 25)
  @Column(name = "last_name", nullable = false)
  private String lastName;

  @Min(18)
  @Column(name = "age", nullable = false)
  private String age;

  @OneToMany(targetEntity = Property.class, mappedBy = "host", cascade = CascadeType.ALL)
  @JsonBackReference
  private List<Property> properties;

  @OneToMany(targetEntity = Payment.class, mappedBy = "host", cascade = CascadeType.ALL)
  private List<Payment> payments;

  @OneToMany(targetEntity = Reservation.class, mappedBy = "guest", cascade = CascadeType.ALL)
  private List<Reservation> reservations;


  @ManyToMany(targetEntity = Role.class, fetch = FetchType.EAGER)
  @JoinTable(
      name = "users_roles",
      joinColumns = @JoinColumn(
          name = "user_id",
          referencedColumnName = "id"
      ),
      inverseJoinColumns = @JoinColumn(
          name = "role_id",
          referencedColumnName = "id"
      )
  )
  private Set<Role> authorities;

  public User() {
    this.enabled = true;
  }

  private boolean enabled;

  public void setUsername(String username) {
    this.username = username;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public void setPassword(String password) {
    this.password = password;
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

  public String getAge() {
    return age;
  }

  public void setAge(String age) {
    this.age = age;
  }

  public List<Property> getProperties() {
    return properties;
  }

  public void setProperties(List<Property> properties) {
    this.properties = properties;
  }

  public List<Payment> getPayments() {
    return payments;
  }

  public void setPayments(List<Payment> payments) {
    this.payments = payments;
  }

  public List<Reservation> getReservations() {
    return reservations;
  }

  public void setReservations(List<Reservation> reservations) {
    this.reservations = reservations;
  }

  public void setAuthorities(Set<Role> authorities) {
    this.authorities = authorities;
  }

  @Override
  public Set<Role> getAuthorities() {
    return this.authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  @Transient
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  @Transient
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  @Transient
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  @Transient
  public boolean isEnabled() {
    return this.enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }
}
