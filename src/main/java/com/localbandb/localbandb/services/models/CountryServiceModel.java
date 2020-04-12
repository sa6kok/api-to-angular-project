package com.localbandb.localbandb.services.models;

import java.util.List;

public class CountryServiceModel {
  private String id;
  private String name;
  private List<CityServiceModel> cities;

  public CountryServiceModel() {
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public List<CityServiceModel> getCities() {
    return cities;
  }

  public void setCities(List<CityServiceModel> cities) {
    this.cities = cities;
  }
}
