package com.localbandb.localbandb.web.api.models;

public class ReservationViewModel {
  private String id;
  private String country;
  private String city;
  private Integer occupancy;
  private String startDate;
  private String endDate;
  private PropertyViewModel property;
  private String totalPrice;
  private ReviewViewModel review;
  private boolean payed;
  private boolean canceled;
  private boolean past;
  private String owner;

  public ReservationViewModel() {
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
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

  public PropertyViewModel getProperty() {
    return property;
  }

  public void setPropertyViewModel(PropertyViewModel property) {
    this.property = property;
  }

  public String getTotalPrice() {
    return totalPrice;
  }

  public void setTotalPrice(String totalPrice) {
    this.totalPrice = totalPrice;
  }

  public ReviewViewModel getReview() {
    return review;
  }

  public void setReview(ReviewViewModel review) {
    this.review = review;
  }

  public boolean isPayed() {
    return payed;
  }

  public void setPayed(boolean payed) {
    this.payed = payed;
  }

  public boolean isCanceled() {
    return canceled;
  }

  public void setCanceled(boolean canceled) {
    this.canceled = canceled;
  }

  public boolean isPast() {
    return past;
  }

  public void setPast(boolean past) {
    this.past = past;
  }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }
}
