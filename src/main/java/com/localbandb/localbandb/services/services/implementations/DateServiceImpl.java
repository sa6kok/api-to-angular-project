package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.services.services.DateService;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Service
public class DateServiceImpl implements DateService {
    @Override
    public LocalDate getDateFromString(String date) {
        return LocalDate.parse(date, DateTimeFormatter.ofPattern("d.MM.yyyy"));
    }

    @Override
    public String getStringFromLocalDate(LocalDate date) {
      return   date.format(DateTimeFormatter.ofPattern("d.MM.yyyy"));
    }
}
