package com.example.agency.repositories;

import com.example.agency.entities.Airline;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AirlineRepository extends JpaRepository<Airline,Long> {
}
