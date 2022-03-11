package com.example.agency.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ContractForClient {


    private Long tourId;

    private Long airlineId;

    private Integer place; // место в самолете

}
