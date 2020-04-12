package com.localbandb.localbandb.services.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import java.math.BigDecimal;

@Getter
@Setter
@NoArgsConstructor
public class PropertyServiceModel {
  private String id;
  private String name;
  private String description;
  private Integer maxOccupancy;
  private BigDecimal price;
  private String pictureUrl;
  private String city;
  private String street;
  private int streetNumber;
  private String streetNumberAddition;
  private int floor;
  private int apartment;

  public String getName() {
    return name;
  }

  public String getPictureUrl() {
    return pictureUrl;
  }

  public void setPictureUrl(String pictureUrl) {
    this.pictureUrl = pictureUrl;
  }

  public String getCity() {
    return city;
  }

  public void setCity(String city) {
    this.city = city;
  }
}
