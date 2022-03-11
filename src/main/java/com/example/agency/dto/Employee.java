package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class Employee {

    private String firstname;

    private String lastname;

    private String email;

    private String password;

    private Long positionId;
}
