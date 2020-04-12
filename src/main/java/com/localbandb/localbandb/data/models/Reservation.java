package com.localbandb.localbandb.data.models;


import com.fasterxml.jackson.annotation.JsonBackReference;

import javax.persistence.*;
import javax.validation.constraints.Min;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "reservations")
public class Reservation extends BaseEntity {


  @Column(name = "start_date", nullable = false)
  private LocalDate startDate;

  @Column(name = "end_date", nullable = false)
  private LocalDate endDate;

  @Column(name = "created", nullable = false)
  private LocalDate created;

  @Min(1)
  private Integer occupancy;

  @ManyToOne(targetEntity = Property.class)
  @JoinColumn(name = "property_id")
  @JsonBackReference
  private Property property;

  @OneToOne(targetEntity = Review.class, cascade = CascadeType.ALL)
  @JoinColumn(name = "review_id", referencedColumnName = "id")
  private Review review;

  @ManyToOne(targetEntity = User.class)
  @JoinColumn(name = "user_id", referencedColumnName = "id")
  @JsonBackReference
  private User guest;

  @Min(0)
  @Column(name = "total_price")
  private BigDecimal totalPrice;

  @OneToMany(targetEntity = Payment.class, mappedBy = "reservation",
          cascade = CascadeType.ALL,
          orphanRemoval = true)
  private List<Payment> payments;

  @Column(name = "is_payed")
  private boolean payed;

  @Column(name = "is_canceled")
  private boolean canceled;

  @Column(name = "is_past")
  private boolean past;

  public Reservation() {
  }

  public LocalDate getStartDate() {
    return startDate;
  }

  public void setStartDate(LocalDate startDate) {
    this.startDate = startDate;
  }

  public LocalDate getEndDate() {
    return endDate;
  }

  public void setEndDate(LocalDate endDate) {
    this.endDate = endDate;
  }

  public LocalDate getCreated() {
    return created;
  }

  public void setCreated(LocalDate created) {
    this.created = created;
  }

  public Integer getOccupancy() {
    return occupancy;
  }

  public void setOccupancy(Integer occupancy) {
    this.occupancy = occupancy;
  }

  public Property getProperty() {
    return property;
  }

  public void setProperty(Property property) {
    this.property = property;
  }

  public Review getReview() {
    return review;
  }

  public void setReview(Review review) {
    this.review = review;
  }

  public User getGuest() {
    return guest;
  }

  public void setGuest(User guest) {
    this.guest = guest;
  }

  public BigDecimal getTotalPrice() {
    return totalPrice;
  }

  public void setTotalPrice(BigDecimal totalPrice) {
    this.totalPrice = totalPrice;
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

  public List<Payment> getPayment() {
    return payments;
  }

  public void setPayment(List<Payment> payments) {
    this.payments = payments;
  }

  public List<Payment> getPayments() {
    return payments;
  }

  public void setPayments(List<Payment> payments) {
    this.payments = payments;
  }

  public boolean isPast() {
    return past;
  }

  public void setPast(boolean past) {
    this.past = past;
  }
}
