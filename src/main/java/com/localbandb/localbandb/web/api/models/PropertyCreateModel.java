package com.localbandb.localbandb.web.api.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
import java.math.BigDecimal;

import static com.localbandb.localbandb.web.api.constants.Constants.*;

@Getter
@Setter
@NoArgsConstructor
public class PropertyCreateModel {

  @Size(min = 6,  message = SHOULD_BE_BETWEEN_3_15_SYMBOLS)
  private String name;

  @Size(min = 15, message = SHOULD_BE_AT_LEAST_15_SYMBOLS)
  private String description;

  @Min(value = 1, message = SHOULD_BE_AT_LEAST_1)
  private Integer maxOccupancy;

  @Min(value = 0, message = SHOULD_BE_A_POSITIVE_NUMBER)
  private BigDecimal price;

  @NotEmpty(message = SHOULD_NOT_BE_EMPTY)
  private String city;

  @Size(min = 3, max = 25, message = SHOULD_BE_BETWEEN_3_15_SYMBOLS)
  private String street;

  @Min(value = 0, message = SHOULD_BE_A_POSITIVE_NUMBER)
  private int streetNumber;


  private String streetNumberAddition;

  @Min(value = 0, message = SHOULD_BE_A_POSITIVE_NUMBER)
  private int floor;

  @Min(value = 0, message = SHOULD_BE_A_POSITIVE_NUMBER)
  private int apartment;

  private String pictureUrl;
}
