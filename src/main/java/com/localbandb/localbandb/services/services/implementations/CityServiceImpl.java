package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.data.models.City;
import com.localbandb.localbandb.data.models.Country;
import com.localbandb.localbandb.data.repositories.CityRepository;
import com.localbandb.localbandb.services.models.CountryServiceModel;
import com.localbandb.localbandb.services.services.CityService;
import com.localbandb.localbandb.services.services.CountryService;
import javassist.NotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CityServiceImpl implements CityService {
  private final CityRepository cityRepository;
  private final CountryService countryService;

  @Autowired
  public CityServiceImpl(CityRepository cityRepository, CountryService countryService) {
    this.cityRepository = cityRepository;
    this.countryService = countryService;
  }

  @Override
  @PreAuthorize("permitAll")
  public void save(City city) throws NotFoundException {
    if (city.getProperties() == null) {
      city.setProperties(new ArrayList<>());
    }
    if(city.getCountry().getName() == null) {
      return;
    }
    cityRepository.save(city);
  }

  @Override
  public boolean addCity(String country, String city) throws NotFoundException {
    City cityFromDb = cityRepository.findByName(city);
    if (cityFromDb != null && cityFromDb.getCountry().getName().equals(country)) {
      return false;
    }
   return countryService.addCityToCountry(city, country);
  }

  @Override
  @PreAuthorize("permitAll")
  public City findCityByName(String name) {
    return cityRepository.findByName(name);
  }

  @Override
  public List<City> findAll() {
    return cityRepository.findAll();
  }
}
