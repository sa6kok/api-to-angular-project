package com.localbandb.localbandb.data.models;

import javax.persistence.Column;
import javax.persistence.Entity;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
public class CustomError extends BaseEntity{
    @Column(name = "exception", columnDefinition = "TEXT")
    String  exception;

    @Column(name = "stack_trace", columnDefinition = "TEXT")
    String  stackTrace;

    @Column(name = "timestamp")
    LocalDateTime dateTime;

    public CustomError() {
    }

    public String getException() {
        return exception;
    }

    public void setException(String exception) {
        this.exception = exception;
    }

    public String getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(String stackTrace) {
        this.stackTrace = stackTrace;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public void setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
    }
}
