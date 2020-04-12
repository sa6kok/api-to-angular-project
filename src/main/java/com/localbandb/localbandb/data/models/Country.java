package com.localbandb.localbandb.data.models;

import com.fasterxml.jackson.annotation.JsonBackReference;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
import java.util.List;

@Entity
@Table(name = "countries")
public class Country extends BaseEntity {

  @NotEmpty
  @Size(min = 3, max = 25)
  @Column(name = "name", unique = true)
  private String name;

  @OneToMany(targetEntity = City.class, mappedBy = "country", cascade = CascadeType.ALL)
  @JsonBackReference
  private List<City> cities;

  public Country() {
  }

  public Country(@NotEmpty @Size(min = 3, max = 25) String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public List<City> getCities() {
    return cities;
  }

  public void setCities(List<City> cities) {
    this.cities = cities;
  }
}
