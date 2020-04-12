package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.data.models.City;
import com.localbandb.localbandb.data.models.Country;
import com.localbandb.localbandb.data.repositories.CountryRepository;
import com.localbandb.localbandb.services.models.CityServiceModel;
import com.localbandb.localbandb.services.models.CountryServiceModel;
import com.localbandb.localbandb.services.services.CountryService;
import com.localbandb.localbandb.web.api.models.CityViewModel;
import com.localbandb.localbandb.web.api.models.CountryViewModel;
import javassist.NotFoundException;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CountryServiceImpl implements CountryService {
  private final CountryRepository countryRepository;
  private final ModelMapper modelMapper;

  @Autowired
  public CountryServiceImpl(CountryRepository countryRepository, ModelMapper modelMapper) {
    this.countryRepository = countryRepository;
    this.modelMapper = modelMapper;
  }

  @Override
  @PreAuthorize("permitAll")
  public List<CountryViewModel> getAllCountryNames() {
    return countryRepository.findAllByOrderByName().stream()
            .map(c -> modelMapper.map(c, CountryViewModel.class)).collect(Collectors.toList());
  }

  @Override
  @PreAuthorize("permitAll")
  public CountryServiceModel findByName(String name) throws NotFoundException {

      Country country = countryRepository.findByName(name);
      if(country == null) {
        throw new NotFoundException("Country not Found!");
      }
     return modelMapper.map(country, CountryServiceModel.class);


  }


  @Override
  public boolean addCityToCountry(String name, String country) throws NotFoundException {
    Country countryFromDB = countryRepository.findByName(country);
    if(country == null) {
      return false;
    }
    try {
      City city = new City();
      city.setCountry(countryFromDB);
      city.setName(name);
      countryFromDB.getCities().add(city);
      countryRepository.saveAndFlush(countryFromDB);
      return  true;
    } catch (Exception ex) {
      return false;
    }
  }

  @Override
  public List<CityViewModel> getOrderedCitiesForCountry(String name) throws NotFoundException {
    return this.findByName(name).getCities().stream().sorted(Comparator.comparing(CityServiceModel::getName))
        .map(c -> modelMapper.map(c,  CityViewModel.class)).collect(Collectors.toList());
  }

  @Override
  public boolean addCountry(String country) {
    Country countryFromDb = countryRepository.findByName(country);

    if(countryFromDb != null) {
      return false;
    }
    try {
      Country countryToSave = new Country();
      countryToSave.setName(country);
      countryRepository.save(countryToSave);
      return true;
    } catch (Exception ex) {
      return false;
    }
  }

  @Override
  public List<CityServiceModel> findOrderedCitiesByCountry(String country) {
    return countryRepository.findByName(country).getCities().stream()
            .map(c -> modelMapper.map(c, CityServiceModel.class))
            .sorted(Comparator.comparing(CityServiceModel::getName)).collect(Collectors.toList());
  }
}
