package com.localbandb.localbandb.web.api.models;

import com.localbandb.localbandb.data.models.City;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class PropertyViewModel {
  private String name;
  private String description;
  private String id;
  private BigDecimal price;
  private String maxOccupancy;
  private String street;
  private Integer streetNumber;
  private String streetNumberAddition;
  private Integer floor;
  private Integer apartment;
  private City city;
  private List<String> pictures;
  private String firstPicture;
  private List<LocalDate> busyDates;
  private List<ReviewViewModel> reviews;
  private String owner;

  public List<String> getPictures() {
    return pictures;
  }

  public void setPictures(List<String> pictures) {
    this.pictures = pictures;
  }

  public String getOwner() {
    return owner;
  }

  public void setOwner(String owner) {
    this.owner = owner;
  }

  public PropertyViewModel() {
    this.pictures = new ArrayList<>();
    this.busyDates = new ArrayList<>();
    this.reviews = new ArrayList<>();
  }



  public String getFirstPicture() {
    if( pictures == null || pictures.size() == 0) {
      return "";
    }
    return pictures.get(0);
  }

  public void setFirstPicture(String firstPicture) {
    this.firstPicture = this.getFirstPicture();
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getDescription() {
    return description;
  }

 /* public String getShortDescription() {
    return description.length() > 75 ?  description.substring(0, 75) + "..." : description;
  }                                */

  public String getFullStreet() {
    StringBuilder sb = new StringBuilder(this.street);
   sb.append(" ").append(this.streetNumber).append(this.streetNumberAddition == null ? "" : this.streetNumberAddition )
           .append(", Floor: ").append(this.floor == null ? "" : this.floor).append(", Apartment: ")
           .append(this.apartment == null ? "" : this.apartment);

   return sb.toString();
  }

  public String getAverageReviews() {
    if(this.reviews.size() == 0) {
      return "No Reviews.";
    }
    Double avg = this.reviews.stream().mapToDouble(ReviewViewModel::getLevel).average().orElse(0.00);

    return String.format("%.2f", avg);
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public BigDecimal getPrice() {
    return price;
  }

  public void setPrice(BigDecimal price) {
    this.price = price;
  }

  public String getMaxOccupancy() {
    return maxOccupancy;
  }

  public void setMaxOccupancy(String maxOccupancy) {
    this.maxOccupancy = maxOccupancy;
  }

  public String getStreet() {
    return street;
  }

  public void setStreet(String street) {
    this.street = street;
  }

  public Integer getStreetNumber() {
    return streetNumber;
  }

  public void setStreetNumber(Integer streetNumber) {
    this.streetNumber = streetNumber;
  }

  public String getStreetNumberAddition() {
    return streetNumberAddition;
  }

  public void setStreetNumberAddition(String streetNumberAddition) {
    this.streetNumberAddition = streetNumberAddition;
  }

  public Integer getFloor() {
    return floor;
  }

  public void setFloor(Integer floor) {
    this.floor = floor;
  }

  public Integer getApartment() {
    return apartment;
  }

  public void setApartment(Integer apartment) {
    this.apartment = apartment;
  }

  public City getCity() {
    return city;
  }

  public void setCity(City city) {
    this.city = city;
  }

  public List<LocalDate> getBusyDates() {
    return busyDates;
  }

  public void setBusyDates(List<LocalDate> busyDates) {
    this.busyDates = busyDates;
  }

  public List<ReviewViewModel> getReviews() {
    return reviews;
  }

  public void setReviews(List<ReviewViewModel> reviews) {
    this.reviews = reviews;
  }
}
