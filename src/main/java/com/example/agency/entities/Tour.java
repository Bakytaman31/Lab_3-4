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
@Table(name = "tour")
public class Tour {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "tour_id")
    private Long id;

    private Date dateStart;

    private Date dateEnd;

    private String name;

    private String description;

    @Enumerated(EnumType.STRING)
    private Status status;

}
