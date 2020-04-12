package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.data.models.Payment;
import com.localbandb.localbandb.data.models.Reservation;
import javassist.NotFoundException;

public interface PaymentService {
    boolean save(Payment payment);

    void createPayment(Reservation reservation) throws NotFoundException;
}
