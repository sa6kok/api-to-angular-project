package com.localbandb.localbandb.data.models;

import javax.persistence.*;
import javax.validation.constraints.Min;
import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Table(name = "payments")
public class Payment extends BaseEntity {

  @Column(name = "amount", nullable = false)
  private BigDecimal amount;

  @ManyToOne(targetEntity = User.class)
  @JoinColumn(name = "user_id", referencedColumnName = "id",  nullable = false)
  private User guest;

  @ManyToOne(targetEntity = User.class)
  @JoinColumn(name = "host_id", referencedColumnName = "id", nullable = false)
  private User host;

  @Column(name = "payment_date", nullable = false)
  private LocalDate paymentDate;

  @ManyToOne(targetEntity = Reservation.class, fetch = FetchType.LAZY)
  @JoinColumn(name = "reservation_id", referencedColumnName = "id", nullable = false)
  private Reservation reservation;

  public Payment() {
  }


  public BigDecimal getAmount() {
    return amount;
  }

  public void setAmount(BigDecimal amount) {
    this.amount = amount;
  }

  public User getGuest() {
    return guest;
  }

  public void setGuest(User guest) {
    this.guest = guest;
  }

  public User getHost() {
    return host;
  }

  public void setHost(User host) {
    this.host = host;
  }

  public LocalDate getPaymentDate() {
    return paymentDate;
  }

  public void setPaymentDate(LocalDate paymentDate) {
    this.paymentDate = paymentDate;
  }

  public Reservation getReservation() {
    return reservation;
  }

  public void setReservation(Reservation reservation) {
    this.reservation = reservation;
  }
}
