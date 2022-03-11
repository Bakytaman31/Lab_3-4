package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ProgramDto {

    private String name;

    private String address;

    private String time;

    private Date date;

    private Long tourId;

}
