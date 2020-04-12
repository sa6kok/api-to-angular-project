package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.data.models.Property;
import com.localbandb.localbandb.data.models.Reservation;
import com.localbandb.localbandb.web.api.models.PropertyCreateModel;
import com.localbandb.localbandb.web.api.models.PropertyViewModel;
import javassist.NotFoundException;

import java.time.LocalDate;
import java.util.List;

public interface PropertyService {

    boolean save(PropertyCreateModel model) throws NotFoundException;

    List<PropertyViewModel> getAllOrderedByAverageReviews();

    List<PropertyViewModel> getAllByCity(String city);

    List<PropertyViewModel> getAllByCountry(String city);

    PropertyViewModel findById(String id) throws NotFoundException;

    void addPropertyToReservation(String propertyId, Reservation model) throws NotFoundException;

    List<LocalDate> getDatesBetweenStartAndEndFromString(String start, String end);

    List<PropertyViewModel> getAllPropertyServiceModelsByCityAndFilterBusyDatesAndOccupancy(String city, String startDate, String endDate, Integer occupancy);

    List<LocalDate> getDatesBetweenStartAndEnd(LocalDate start, LocalDate end);

    List<String> getListDatesBetweenStartAndEndFromString(String startDate, String endDate);

  String getJointlyDates(String propertyId, String startDate, String endDate);

    List<PropertyViewModel> getMyProperties();

    boolean addPictureToProperty(String id, String pictureUrl);

    PropertyViewModel getPropertyViewModel(Property p);

    boolean eraseBusyDatesFromCancel(String id, LocalDate startDate, LocalDate endDate);

    String getOwnerUsername(String id);

    boolean checkIfUserIsPropertyOwner(String propertyId);
}

