package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.config.authentication.AuthenticationFacade;
import com.localbandb.localbandb.data.models.*;
import com.localbandb.localbandb.data.repositories.PropertyRepository;
import com.localbandb.localbandb.services.models.PropertyServiceModel;
import com.localbandb.localbandb.services.services.CityService;
import com.localbandb.localbandb.services.services.DateService;
import com.localbandb.localbandb.services.services.PropertyService;
import com.localbandb.localbandb.services.services.UserService;
import com.localbandb.localbandb.web.api.models.PropertyCreateModel;
import com.localbandb.localbandb.web.api.models.PropertyViewModel;
import com.localbandb.localbandb.web.api.models.ReviewViewModel;
import javassist.NotFoundException;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class PropertyServiceImpl implements PropertyService {
    private final PropertyRepository propertyRepository;
    private final CityService cityService;
    private final UserService userService;
    private final DateService dateService;
    private final ModelMapper modelMapper;
    private final AuthenticationFacade authenticationFacade;

    @Autowired
    public PropertyServiceImpl(PropertyRepository propertyRepository, CityService cityService, UserService userService, DateService dateService, ModelMapper modelMapper, AuthenticationFacade authenticationFacade) {
        this.propertyRepository = propertyRepository;
        this.cityService = cityService;
        this.userService = userService;
        this.dateService = dateService;
        this.modelMapper = modelMapper;
        this.authenticationFacade = authenticationFacade;
    }

    @Override
    @Secured("ROLE_HOST")
    public boolean save(PropertyCreateModel model) throws NotFoundException {
        PropertyServiceModel propertyServiceModel = modelMapper.map(model, PropertyServiceModel.class);
        City city = cityService.findCityByName(propertyServiceModel.getCity());
        Property property = modelMapper.map(propertyServiceModel, Property.class);
        String username = authenticationFacade.getAuthentication().getName();
        User user = userService.findByUsername(username);

        property.setHost(user);
        property.setCity(city);
        if (property.getPictures() == null) {
            property.setPictures(new ArrayList<>());
        }
        if (property.getBusyDates() == null) {
            property.setBusyDates(new ArrayList<>());
        }
        if (property.getReservations() == null) {
            property.setReservations(new ArrayList<>());
        }

        property.getPictures().add(propertyServiceModel.getPictureUrl());
        try {
            propertyRepository.save(property);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    @Override
    @PreAuthorize("permitAll")
    public List<PropertyViewModel> getAllOrderedByAverageReviews() {
        List<Property> properties = propertyRepository.findAll();
        List<Property> propertiesOrdered = orderByAverageReviews(properties);
        return getPropertyViewModelsFromProperty(propertiesOrdered);
    }

    private List<Property> orderByAverageReviews(List<Property> properties) {
      return   properties.stream()
        .sorted((f, s) -> {
            double first = f.getReviews().stream().mapToInt(Review::getLevel).average().orElse(0.00);
            double second = s.getReviews().stream().mapToInt(Review::getLevel).average().orElse(0.00);

            return Double.compare(second, first);
        }).collect(Collectors.toList());
    }


    @Override
    @PreAuthorize("permitAll")
    public List<PropertyViewModel> getAllByCity(String city) {
        List<Property> properties = propertyRepository.findByCity_Name(city);
        return getPropertyViewModelsFromProperty(this.orderByAverageReviews(properties));
    }

    @Override
    public List<PropertyViewModel> getAllByCountry(String country) {
        return propertyRepository.findAllByCity_Country_Name(country)
                .stream().map(c -> modelMapper.map(c, PropertyViewModel.class)).collect(Collectors.toList());
    }

    @Override
   // @Secured({"ROLE_HOST", "ROLE_GUEST"})
    public PropertyViewModel findById(String id) throws NotFoundException {
        Optional<Property> byId = propertyRepository.findById(id);
        if (byId.isEmpty()) {
            throw new NotFoundException("Property not found");
        }
        Property property = byId.get();
        return this.getPropertyViewModel(property);
    }

    @Override
    @PreAuthorize("permitAll")
    public List<PropertyViewModel> getAllPropertyServiceModelsByCityAndFilterBusyDatesAndOccupancy(String city, String startDate, String endDate, Integer occupancy) {
        List<LocalDate> busyDates = this.getDatesBetweenStartAndEndFromString(startDate, endDate);
        List<Property> properties = propertyRepository.findByCity_Name(city).stream()
                .filter(p -> !p.getBusyDates().containsAll(busyDates))
                .filter(prop -> prop.getMaxOccupancy() >= occupancy)
                .collect(Collectors.toList());
        return this.getPropertyViewModelsFromProperty(properties);
    }


    @Override
   // @Secured({"ROLE_GUEST"})
    public void addPropertyToReservation(String propertyId, Reservation model) throws NotFoundException {
        Property property = propertyRepository.findById(propertyId).orElseThrow(() -> new NotFoundException("Property not found"));
        List<LocalDate> dates = this.getDatesBetweenStartAndEnd(model.getStartDate(), model.getEndDate());
        property.getBusyDates().addAll(dates);
        Property savedProperty = propertyRepository.saveAndFlush(property);
        model.setProperty(savedProperty);
    }


    @Override
    @PreAuthorize("permitAll")
    public List<LocalDate> getDatesBetweenStartAndEndFromString(String start, String end) {
        LocalDate startDate = dateService.getDateFromString(start);
        LocalDate endDate = dateService.getDateFromString(end);
        return getDatesBetweenStartAndEnd(startDate, endDate);
    }

    @Override
    @PreAuthorize("permitAll")
    public List<LocalDate> getDatesBetweenStartAndEnd(LocalDate start, LocalDate end) {
        List<LocalDate> ret = new ArrayList<>();
        for (LocalDate date = start; date.isBefore(end); date = date.plusDays(1)) {
            ret.add(date);
        }
        return ret;
    }

    @Override
    @PreAuthorize("permitAll")
    public List<String> getListDatesBetweenStartAndEndFromString(String startDate, String endDate) {
        List<String> collect = this.getDatesBetweenStartAndEndFromString(startDate, endDate).stream()
                .map(dateService::getStringFromLocalDate).collect(Collectors.toList());
        return collect;
    }

    @Override
    @PreAuthorize("permitAll")
    public String getJointlyDates(String propertyId, String startDate, String endDate) {
        List<String> requestedDates = getListDatesBetweenStartAndEndFromString(startDate, endDate);
        List<String> busyDates = propertyRepository.findById(propertyId).get().getBusyDates()
                .stream().map(dateService::getStringFromLocalDate).collect(Collectors.toList());
        busyDates.retainAll(requestedDates);
        if (busyDates.size() == 0) {
            return "";
        }
        List<String> collect = busyDates.stream().sorted(String::compareTo).collect(Collectors.toList());
        return String.join(", ", collect);
    }

    @Override
   // @Secured("ROLE_HOST")
    public List<PropertyViewModel> getMyProperties() {

        String username = authenticationFacade.getAuthentication().getName();
        List<Property> myProperties = propertyRepository.findAllByHost_Username(username);

        return this.getPropertyViewModelsFromProperty(myProperties);
    }

    @Override
    @Secured("ROLE_HOST")
    public boolean addPictureToProperty(String id, String pictureUrl) {
        try {
            Property property = propertyRepository.findById(id).orElseThrow();
            String saveUsername = authenticationFacade.getAuthentication().getName();
            String hostUsername = property.getHost().getUsername();
            if(!hostUsername.equals(saveUsername)) {
                return false;
            }
            property.getPictures().add(pictureUrl);
            propertyRepository.saveAndFlush(property);
            return true;
        } catch (Exception ex) {
            return  false;
        }
    }

    @PreAuthorize("permitAll")
    public List<PropertyViewModel> getPropertyViewModelsFromProperty(List<Property> properties) {
        return properties.stream()
                .map(this::getPropertyViewModel).collect(Collectors.toList());
    }

    @Override
    @PreAuthorize("permitAll")
    public PropertyViewModel getPropertyViewModel(Property p) {
        List<ReviewViewModel> reviewViewModels = p.getReviews().stream()
                .map(rev -> modelMapper.map(rev, ReviewViewModel.class)).collect(Collectors.toList());
        PropertyViewModel propertyViewModel = modelMapper.map(p, PropertyViewModel.class);
        propertyViewModel.setReviews(reviewViewModels);
        propertyViewModel.setOwner(p.getHost().getUsername());
        return propertyViewModel;
    }

    @Override
    @PreAuthorize("permitAll")
    public boolean eraseBusyDatesFromCancel(String id, LocalDate startDate, LocalDate endDate) {
        try {
            Property property = propertyRepository.findById(id).orElseThrow();

            List<LocalDate> busyDates = property.getBusyDates();
            List<LocalDate> daysToCancel = this.getDatesBetweenStartAndEnd(startDate, endDate);
            List<LocalDate> collect = busyDates.stream().filter(o -> !daysToCancel.contains(o)).collect(Collectors.toList());
            property.setBusyDates(collect);
            propertyRepository.saveAndFlush(property);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public String getOwnerUsername(String id) {
        return propertyRepository.findById(id).orElseThrow().getHost().getUsername();
    }

    @Override
    public boolean checkIfUserIsPropertyOwner(String propertyId) {
        String owner = this.getOwnerUsername(propertyId);
        return authenticationFacade.getAuthentication().getName().equals(owner);
    }

}
