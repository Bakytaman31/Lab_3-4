package com.example.agency.entities;

import com.example.agency.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "tickets")//авиа билеты + тур (как путевка)
public class Tickets {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "tickets_id")
    private Long id;

    @ManyToOne
    private User user;

    private Integer place; // место

    @ManyToOne
    private Tour tour;

    private Date dateOfRegistration;

    @ManyToOne
    private Airline airline;

    @Enumerated(EnumType.STRING)
    private Status status;

    @ManyToOne
    private Clients clients;
}
