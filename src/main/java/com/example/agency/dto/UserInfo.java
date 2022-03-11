package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserInfo {

    private String firstname;

    private String lastname;

    private String email;

    private String phoneNumber;

    private String role;

    private String position;
}
