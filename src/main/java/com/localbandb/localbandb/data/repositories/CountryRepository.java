package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.Country;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CountryRepository extends JpaRepository<Country, String> {
  Country findByName(String name);

  List<Country> findAllByOrderByName();
}
