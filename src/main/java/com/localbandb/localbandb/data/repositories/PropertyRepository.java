package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.Property;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PropertyRepository extends JpaRepository<Property, String> {
  List<Property> findByCity_Name(String city);

  List<Property> findAllByHost_Username(String username);

  List<Property> findAllByCity_Country_Name(String country);
}
