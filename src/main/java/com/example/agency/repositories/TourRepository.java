package com.example.agency.repositories;

import com.example.agency.entities.Tour;
import com.example.agency.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TourRepository extends JpaRepository<Tour,Long> {

    List<Tour> findByStatus(Status status);

    Tour findByStatusAndId(Status status, Long id);

    Tour findByNameAndStatus(String name, Status status);

}
