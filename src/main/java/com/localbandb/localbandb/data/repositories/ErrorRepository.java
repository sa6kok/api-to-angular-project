package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.CustomError;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ErrorRepository extends JpaRepository<CustomError, String> {
}
