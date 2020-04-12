package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.config.authentication.AuthenticationFacade;
import com.localbandb.localbandb.data.models.BaseEntity;
import com.localbandb.localbandb.data.models.Payment;
import com.localbandb.localbandb.data.models.Reservation;
import com.localbandb.localbandb.data.repositories.ReservationRepository;
import com.localbandb.localbandb.services.services.*;
import com.localbandb.localbandb.web.api.models.PropertyViewModel;
import com.localbandb.localbandb.web.api.models.ReservationCreateModel;
import com.localbandb.localbandb.web.api.models.ReservationViewModel;
import javassist.NotFoundException;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ReservationServiceImpl implements ReservationService {
    private final PropertyService propertyService;
    private final DateService dateService;
    private final UserService userService;
    private final PaymentService paymentService;
    private final ReservationRepository reservationRepository;
    private final AuthenticationFacade authenticationFacade;
    private final ModelMapper mapper;

    @Autowired
    public ReservationServiceImpl(PropertyService propertyService, DateService dateService, UserService userService, PaymentService paymentService, ReservationRepository reservationRepository, AuthenticationFacade authenticationFacade, ModelMapper mapper) {
        this.propertyService = propertyService;
        this.dateService = dateService;
        this.userService = userService;
        this.paymentService = paymentService;
        this.reservationRepository = reservationRepository;
        this.authenticationFacade = authenticationFacade;
        this.mapper = mapper;
    }


    @Override
   // @Secured("ROLE_GUEST")
    public boolean create( ReservationCreateModel model) {

        try {
            Reservation reservation = mapper.map(model, Reservation.class);
            reservation.setStartDate(dateService.getDateFromString(model.getStartDate()));
            reservation.setEndDate(dateService.getDateFromString(model.getEndDate()));
            propertyService.addPropertyToReservation(model.getPropertyId(), reservation);
            userService.addUserToReservation(reservation);
            reservation.setPayment(new ArrayList<>());
            reservation.setCreated(LocalDate.now());
            Reservation savedReservation = reservationRepository.save(reservation);

            if (model.isCheckPayment()) {
                this.addPaymentToReservation(savedReservation, model.getTotalPrice());
                Reservation reservationToCheck = reservationRepository.findById(savedReservation.getId()).get();
                if (this.checkIfItIsPayed(reservationToCheck)) {
                    reservationToCheck.setPayed(true);
                    reservationRepository.saveAndFlush(reservationToCheck);
                }
            }
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    @Override
   // @Secured("ROLE_GUEST")
    public Reservation save(Reservation reservation) {
        return reservationRepository.saveAndFlush(reservation);
    }

    @Override
   // @Secured("ROLE_GUEST")
    public ReservationCreateModel fillUpModel(String id, String start, String end, String pax) throws NotFoundException {
        ReservationCreateModel reservationCreateModel = new ReservationCreateModel();
        reservationCreateModel.setStartDate(start);
        reservationCreateModel.setEndDate(end);
        reservationCreateModel.setOccupancy(Integer.parseInt(pax));
        reservationCreateModel.setPropertyId(id);
        return reservationCreateModel;
    }

    @Override
   // @Secured("ROLE_GUEST")
    public ReservationCreateModel fillUpModel(String id) throws NotFoundException {
        ReservationCreateModel reservationCreateModel = new ReservationCreateModel();
        reservationCreateModel.setPropertyId(id);
        return reservationCreateModel;
    }

    @Override
   // @Secured("ROLE_GUEST")
    public void addPaymentToReservation(Reservation savedReservation, String totalPrice) throws NotFoundException {
        paymentService.createPayment(savedReservation);
    }

    @Override
   // @Secured({"ROLE_GUEST", "ROLE_HOST"})
    public List<ReservationViewModel> findReservationsForUserWithFilter(String filter) {
        List<Reservation> reservations = new ArrayList<>();
        String username = authenticationFacade.getAuthentication().getName();
        switch (filter) {
            case "payed":
                reservations = reservationRepository.findAllByGuest_Username_AndPayedOrderByStartDateAsc(username, true);
                break;
            case "notPayed":
                reservations = reservationRepository.findAllByGuest_Username_AndPayedOrderByStartDateAsc(username, false);
                break;
            case "all":
                reservations = reservationRepository.findAllByGuest_UsernameOrderByStartDateAsc(username);
                break;
            case "future":
                reservations = reservationRepository.findAllByGuest_Username_AndPastOrderByEndDateAsc(username, false);
                break;
            case "past":
                reservations = reservationRepository.findAllByGuest_Username_AndPastOrderByEndDateAsc(username, true);
                break;
            case "canceled":
                reservations = reservationRepository.findAllByGuest_Username_AndCanceledOrderByStartDateAsc(username, true);
                break;
            case "properties":
                reservations = reservationRepository.findAllByProperty_Host_Username(username);
                break;
            case "admin":
                reservations = reservationRepository.findAll();
        }
        return getReservationViewModelsFromReservation(reservations, username);
    }
    private List<ReservationViewModel> getReservationViewModelsFromReservation(List<Reservation> reservationRepositoryAllByGuestUsername, String username) {
        return reservationRepositoryAllByGuestUsername.stream()
                .map(r -> {
                    PropertyViewModel pvm = propertyService.getPropertyViewModel(r.getProperty());
                    ReservationViewModel rvm = mapper.map(r, ReservationViewModel.class);
                    rvm.setPropertyViewModel(pvm);
                    rvm.setOwner(username);
                    return rvm;
                }).collect(Collectors.toList());
    }

    @Override
   // @Secured("ROLE_GUEST")
    public boolean payReservation(String id) {

        try {
            Reservation reservation = reservationRepository.findById(id).orElseThrow();
            this.addPaymentToReservation(reservation, reservation.getTotalPrice().toString());
            Reservation savedReservation = reservationRepository.findById(id).orElseThrow();
            if (this.checkIfItIsPayed(savedReservation)) {
                savedReservation.setPayed(true);
                reservationRepository.saveAndFlush(savedReservation);
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    @PreAuthorize("permitAll")
    public boolean cancelReservation(String id) {
        String currentUsername = authenticationFacade.getAuthentication().getName();
        try {
            Reservation reservation = reservationRepository.findById(id).orElseThrow();
            if (!reservation.getGuest().getUsername().equals(currentUsername)) {
                return false;
            }
            if(!reservation.isCanceled()) {
                reservation.setCanceled(true);
            }
            reservationRepository.saveAndFlush(reservation);
            propertyService.eraseBusyDatesFromCancel(reservation.getProperty().getId(), reservation.getStartDate(), reservation.getEndDate());
            return true;
        } catch (Exception ex) {
            return false;
        }


    }

    @Override
    @Secured("ROLE_GUEST")
    public Reservation findById(String reservationId) throws NotFoundException {
        return reservationRepository.findById(reservationId).orElseThrow(() -> new NotFoundException("Not Found"));
    }

    @Override
    public void findReservationsToCancelAndCancelAutomaticScheduled() {
        List<Reservation> allByNotPayedAndNotCanceledAndNotPast = reservationRepository
                .findAllByPayedAndCanceledAndPast(false, false, false);
       allByNotPayedAndNotCanceledAndNotPast.stream().filter(this::findIfResaIsOlderThanOneDay)
               .map(BaseEntity::getId).forEach(this::cancelReservation);
    }

    @Override
    public void findReservationToSetPastTrueAutomaticScheduled() {
        List<Reservation> allByPayedAndNotCanceledNotPast = reservationRepository
                .findAllByPayedAndCanceledAndPast(true, false, false);
        allByPayedAndNotCanceledNotPast.stream()
                .filter(this::findIfResaEndDateIsOlderThanOneDay).forEach(r -> r.setPast(true));
        reservationRepository.saveAll(allByPayedAndNotCanceledNotPast);
    }

    private boolean findIfResaIsOlderThanOneDay(Reservation reservation) {
        LocalDate created = reservation.getCreated();
        LocalDate today = LocalDate.now();
        LocalDate diff = today.minusDays(1);
        return diff.isAfter(created);
    }

    private boolean findIfResaEndDateIsOlderThanOneDay(Reservation reservation) {
        LocalDate created = reservation.getEndDate();
        LocalDate today = LocalDate.now();
        LocalDate diff = today.minusDays(1);
        return diff.isAfter(created);
    }

    private boolean checkIfItIsPayed(Reservation savedReservation) {
        BigDecimal sum = savedReservation.getPayment().stream().map(Payment::getAmount).reduce(BigDecimal::add).orElse(BigDecimal.ZERO);
        return sum.compareTo(savedReservation.getTotalPrice()) >= 0;
    }

}
