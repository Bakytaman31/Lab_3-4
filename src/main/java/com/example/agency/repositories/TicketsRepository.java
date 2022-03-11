package com.example.agency.repositories;

import com.example.agency.entities.Tickets;
import com.example.agency.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TicketsRepository extends JpaRepository<Tickets,Long> {

    Tickets findByStatusAndAirline_Id(Status status,Long id);

    List<Tickets> findByStatus(Status status);
}
