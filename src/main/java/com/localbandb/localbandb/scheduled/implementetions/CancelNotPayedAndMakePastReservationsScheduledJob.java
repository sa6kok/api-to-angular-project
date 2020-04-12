package com.localbandb.localbandb.scheduled.implementetions;

import com.localbandb.localbandb.scheduled.ScheduledJob;
import com.localbandb.localbandb.services.services.ReservationService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


@Component
public class CancelNotPayedAndMakePastReservationsScheduledJob implements ScheduledJob {


    private final ReservationService reservationService;

    public CancelNotPayedAndMakePastReservationsScheduledJob(ReservationService reservationService) {
        this.reservationService = reservationService;
    }

    @Override
    @Scheduled(cron = "0 0 2 ? * * *")
    public void scheduledJob() {
        reservationService.findReservationsToCancelAndCancelAutomaticScheduled();
        reservationService.findReservationToSetPastTrueAutomaticScheduled();
    }
}
