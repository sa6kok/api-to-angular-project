package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.data.models.City;
import javassist.NotFoundException;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

public interface CityService {

  void save(City city) throws NotFoundException;

  boolean addCity(String city, String country) throws NotFoundException;

  City findCityByName(String name);

  List<City> findAll();
}
