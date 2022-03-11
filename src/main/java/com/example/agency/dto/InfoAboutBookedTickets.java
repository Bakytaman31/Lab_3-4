package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class InfoAboutBookedTickets {

    private String tour;

    private String airline;

    private Integer place;

    private String nameClient;

    private String phoneNumClient;

    private Date dateOfRegistration;

}
