package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class TourDto {

    private Date dateStart;

    private Date dateEnd;

    private String name;

    private String description;

    private Long programId;

    private Long eventId;
}
