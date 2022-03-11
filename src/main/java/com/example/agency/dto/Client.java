package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class Client {

    private String firstName;

    private String lastname;

    private String email;

    private String phoneNumber;

    private String userPassword;

    private String passportNumber;

    private Integer age;
}
