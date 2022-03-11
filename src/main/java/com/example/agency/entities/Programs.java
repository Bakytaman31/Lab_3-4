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
@Table(name = "programs")
public class Programs {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String address;

    private String time;

    private Date date;

    @Enumerated(EnumType.STRING)
    private Status status;

    @ManyToOne
    private Tour tour;

}
