package com.localbandb.localbandb.web.api.controlers;

import com.google.gson.Gson;
import com.localbandb.localbandb.services.services.PropertyService;
import com.localbandb.localbandb.services.services.ReservationService;
import com.localbandb.localbandb.web.api.models.PropertyViewModel;
import com.localbandb.localbandb.web.api.models.ReservationCreateModel;
import com.localbandb.localbandb.web.api.models.ReservationViewModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
@RequestMapping("/reservation")
public class ReservationController extends BaseController {
    private final ReservationService reservationService;
    private final PropertyService propertyService;
    private final Gson gson;

    @Autowired
    public ReservationController(ReservationService reservationService, PropertyService propertyService, Gson gson) {
        this.reservationService = reservationService;
        this.propertyService = propertyService;
        this.gson = gson;
    }

    @GetMapping("/create/{city}/{start}/{end}/{pax}")
    public List<PropertyViewModel> createWithDates(@PathVariable String city,
                                                   @PathVariable String start,
                                                   @PathVariable String end,
                                                   @PathVariable int pax) {
        return propertyService.getAllPropertyServiceModelsByCityAndFilterBusyDatesAndOccupancy(city, start, end, pax);
    }

    @PostMapping("/details/create")
    @Secured("ROLE_GUEST")
    public boolean createReservationConfirm(@RequestBody ReservationCreateModel model) {
        return reservationService.create(model);
    }

    @GetMapping("/check/{id}/{start}/{end}")
    public String checkBusyDates(@PathVariable String id, @PathVariable String start, @PathVariable String end) {
        String jointlyDates = propertyService.getJointlyDates(id, start, end);
        return gson.toJson(jointlyDates);
    }


    @GetMapping("/reservations/{filter}")
    public List<ReservationViewModel> showReservations(@PathVariable String filter) {
        return reservationService.findReservationsForUserWithFilter(filter);
    }

    @GetMapping("/pay/{id}")
    @Secured("ROLE_GUEST")
    public boolean payReservation(@PathVariable String id) {
        return reservationService.payReservation(id);
    }

    @GetMapping("/cancel/{id}")
    @Secured("ROLE_GUEST")
    public boolean cancelReservation(@PathVariable String id) {
        return reservationService.cancelReservation(id);
    }

}
