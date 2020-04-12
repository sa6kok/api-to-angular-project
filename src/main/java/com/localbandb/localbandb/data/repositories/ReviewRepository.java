package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ReviewRepository extends JpaRepository<Review, String> {
}
