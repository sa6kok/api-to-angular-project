package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.City;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CityRepository extends JpaRepository<City, String> {
  City findByName(String name);
}
