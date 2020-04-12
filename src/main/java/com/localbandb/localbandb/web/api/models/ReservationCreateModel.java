package com.localbandb.localbandb.web.api.models;

import javax.validation.constraints.Size;

import static com.localbandb.localbandb.web.api.constants.Constants.THE_DATE_IS_NOT_CORRECT;

public class ReservationCreateModel {
  private String country;
  private String city;
  private Integer occupancy;
  @Size(min = 8, max = 10, message = THE_DATE_IS_NOT_CORRECT)
  private String startDate;
  @Size(min = 8, max = 10, message = THE_DATE_IS_NOT_CORRECT)
  private String endDate;
  private String propertyId;
  private String totalPrice;
  private boolean checkPayment;



  public ReservationCreateModel() {
  }

  public ReservationCreateModel(Integer occupancy, String startDate, String endDate, String propertyId) {
    this.occupancy = occupancy;
    this.startDate = startDate;
    this.endDate = endDate;
    this.propertyId = propertyId;
  }

  public ReservationCreateModel(String propertyId) {
    this.propertyId = propertyId;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public String getCity() {
    return city;
  }

  public void setCity(String city) {
    this.city = city;
  }

  public Integer getOccupancy() {
    return occupancy;
  }

  public void setOccupancy(Integer occupancy) {
    this.occupancy = occupancy;
  }

  public String getStartDate() {
    return startDate;
  }

  public void setStartDate(String startDate) {
    this.startDate = startDate;
  }

  public String getEndDate() {
    return endDate;
  }

  public void setEndDate(String endDate) {
    this.endDate = endDate;
  }

  public String getPropertyId() {
    return propertyId;
  }

  public void setPropertyId(String propertyId) {
    this.propertyId = propertyId;
  }

  public String getTotalPrice() {
    return totalPrice;
  }

  public void setTotalPrice(String totalPrice) {
    this.totalPrice = totalPrice;
  }
  public boolean isCheckPayment() {
    return checkPayment;
  }

  public void setCheckPayment(boolean checkPayment) {
    this.checkPayment = checkPayment;
  }
}
