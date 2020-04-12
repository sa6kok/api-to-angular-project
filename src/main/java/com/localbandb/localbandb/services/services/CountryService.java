package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.services.models.CityServiceModel;
import com.localbandb.localbandb.services.models.CountryServiceModel;
import com.localbandb.localbandb.web.api.models.CityViewModel;
import com.localbandb.localbandb.web.api.models.CountryViewModel;
import javassist.NotFoundException;

import java.util.List;

public interface CountryService {

  List<CountryViewModel> getAllCountryNames();

  CountryServiceModel findByName(String name) throws NotFoundException;

  boolean addCityToCountry(String name, String country) throws NotFoundException;

  List<CityViewModel> getOrderedCitiesForCountry(String name) throws NotFoundException;

  boolean addCountry(String country);

  List<CityServiceModel> findOrderedCitiesByCountry(String country);
}
