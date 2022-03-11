package com.example.agency.entities;

import com.example.agency.enums.Status;
import com.example.agency.enums.TypeRoom;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "rooms")
public class Rooms {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer number;

    @Enumerated(EnumType.STRING)
    private TypeRoom typeRoom;

    @ManyToOne
    private Hotel hotel;


    @Enumerated(EnumType.STRING)
    private Status status;

}
