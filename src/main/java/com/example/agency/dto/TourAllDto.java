package com.example.agency.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class TourAllDto {

    private Date dateStart;

    private Date dateEnd;

    private String name;

    private String description;

    private List<String> program;

    private  List<String> event;

}
