package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.web.api.models.ReviewCreateModel;

public interface ReviewService {

    boolean save(ReviewCreateModel model, String reservationId);
}
