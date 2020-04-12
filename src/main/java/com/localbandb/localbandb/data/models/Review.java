package com.localbandb.localbandb.data.models;



import com.fasterxml.jackson.annotation.JsonBackReference;

import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.Size;


@Entity
@Table(name = "reviews")
public class Review extends BaseEntity {

  @Column(name = "level")
  private Integer level;

  @Column(name = "description", columnDefinition = "TEXT", nullable = false)
  private String description;

  @OneToOne(targetEntity = Reservation.class, cascade = CascadeType.ALL)
  @JoinColumn(name = "reservation_id", referencedColumnName = "id")
  @JsonBackReference
  private Reservation reservation;

  @ManyToOne(targetEntity = Property.class, cascade = CascadeType.ALL)
  @JoinColumn(name = "property_id", referencedColumnName = "id")
  @JsonBackReference
  private Property property;

  public Review() {
  }

  public Integer getLevel() {
    return level;
  }

  public void setLevel(Integer level) {
    this.level = level;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public Reservation getReservation() {
    return reservation;
  }

  public void setReservation(Reservation reservation) {
    this.reservation = reservation;
  }

  public Property getProperty() {
    return property;
  }

  public void setProperty(Property property) {
    this.property = property;
  }
}
