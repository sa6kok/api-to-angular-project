package com.localbandb.localbandb.config;


import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ModelMapperConfiguration {

  @Bean
  public ModelMapper getModelMapper() {
    ModelMapper mapper = new ModelMapper();
    return mapper;
  }

}
