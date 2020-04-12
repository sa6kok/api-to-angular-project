package com.localbandb.localbandb.services.services;

import java.time.LocalDate;

public interface DateService {
    LocalDate getDateFromString(String date);

    String getStringFromLocalDate(LocalDate date);
}
