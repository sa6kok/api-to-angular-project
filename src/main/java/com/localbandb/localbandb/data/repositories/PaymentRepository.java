package com.localbandb.localbandb.data.repositories;

import com.localbandb.localbandb.data.models.Payment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentRepository extends JpaRepository<Payment, String> {
}
