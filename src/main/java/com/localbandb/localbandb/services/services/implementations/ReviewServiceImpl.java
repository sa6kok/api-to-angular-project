package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.data.models.Reservation;
import com.localbandb.localbandb.data.models.Review;
import com.localbandb.localbandb.data.repositories.ReviewRepository;
import com.localbandb.localbandb.services.services.ReservationService;
import com.localbandb.localbandb.services.services.ReviewService;
import com.localbandb.localbandb.web.api.models.ReviewCreateModel;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class ReviewServiceImpl implements ReviewService {
    private final ReservationService reservationService;
    private final ReviewRepository reviewRepository;
    private final ModelMapper mapper;

    public ReviewServiceImpl(ReservationService reservationService, ReviewRepository reviewRepository, ModelMapper mapper) {
        this.reservationService = reservationService;
        this.reviewRepository = reviewRepository;
        this.mapper = mapper;
    }


    @Override
    @Secured("ROLE_GUEST")
    public boolean save(ReviewCreateModel model, String reservationId) {
        try {
            Reservation reservation = reservationService.findById(reservationId);
            Review review = mapper.map(model, Review.class);
            review.setReservation(reservation);
            review.setProperty(reservation.getProperty());
            Review saved = reviewRepository.save(review);
            reservation.setReview(saved);
            Reservation savedReservation = reservationService.save(reservation);
            savedReservation.getProperty().getReviews().add(saved);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}
