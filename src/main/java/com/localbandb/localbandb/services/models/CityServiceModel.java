package com.localbandb.localbandb.services.models;


import com.localbandb.localbandb.data.models.Country;
import com.localbandb.localbandb.data.models.Property;

import java.util.List;

public class CityServiceModel {

  private String name;
  private Country country;
  private List<Property> properties;


  public CityServiceModel() {
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Country getCountry() {
    return country;
  }

  public void setCountry(Country country) {
    this.country = country;
  }

  public List<Property> getProperties() {
    return properties;
  }

  public void setProperties(List<Property> properties) {
    this.properties = properties;
  }
}
