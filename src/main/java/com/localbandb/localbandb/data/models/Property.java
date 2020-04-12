package com.localbandb.localbandb.data.models;


import com.fasterxml.jackson.annotation.JsonBackReference;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Min;
import javax.validation.constraints.Size;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;


@Entity
@Table(name = "properties")
public class Property extends BaseEntity {


  @Size(min = 6)
  @Column(name = "name", nullable = false)
  private String name;

  @ManyToOne(targetEntity = User.class)
  @JsonBackReference
  private User host;

  @Size(min = 15)
  @Column(name = "description",columnDefinition = "TEXT")
  private String description;

  @Min(1)
  private Integer maxOccupancy;


  @ElementCollection(targetClass = LocalDate.class)
  @Column(name = "busy_dates")
  private List<LocalDate> busyDates;

  @OneToMany(targetEntity = Reservation.class, mappedBy = "property", cascade = CascadeType.ALL)
  @JsonBackReference
  private List<Reservation> reservations;

  @OneToMany(targetEntity = Review.class, mappedBy = "property", cascade = CascadeType.ALL)
  private List<Review> reviews;

  @ElementCollection(targetClass = String.class)
  private List<String> pictures;

  @Min(0)
  @Column(name = "price", nullable = false)
  private BigDecimal price;

  @Size(min = 3, max = 25)
  @Column(name = "street", nullable = false)
  private String street;

  @Min(0)
  @Column(name = "streetNumber", nullable = false)
  private Integer streetNumber;


  @Column(name = "streetNumberAddition")
  private String streetNumberAddition;

  @Min(0)
  @Column(name = "floor")
  private Integer floor;

  @Min(0)
  @Column(name = "apartment")
  private Integer apartment;

  @ManyToOne(targetEntity = City.class)
  @JoinColumn(name = "city_id", referencedColumnName = "id")
  @JsonBackReference
  private City city;

  public Property() {
  }


  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public User getHost() {
    return host;
  }

  public void setHost(User host) {
    this.host = host;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public Integer getMaxOccupancy() {
    return maxOccupancy;
  }

  public void setMaxOccupancy(Integer maxOccupancy) {
    this.maxOccupancy = maxOccupancy;
  }

  public List<LocalDate> getBusyDates() {
    return busyDates;
  }

  public void setBusyDates(List<LocalDate> busyDates) {
    this.busyDates = busyDates;
  }

  public List<Reservation> getReservations() {
    return reservations;
  }

  public void setReservations(List<Reservation> reservations) {
    this.reservations = reservations;
  }

  public List<Review> getReviews() {
    return reviews;
  }

  public void setReviews(List<Review> reviews) {
    this.reviews = reviews;
  }

  public List<String> getPictures() {
    return pictures;
  }

  public void setPictures(List<String> pictures) {
    this.pictures = pictures;
  }

  public BigDecimal getPrice() {
    return price;
  }

  public void setPrice(BigDecimal price) {
    this.price = price;
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
}
