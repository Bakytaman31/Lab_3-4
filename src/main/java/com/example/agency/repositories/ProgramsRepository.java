package com.example.agency.repositories;

import com.example.agency.entities.Programs;
import com.example.agency.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProgramsRepository extends JpaRepository<Programs,Long> {

    List<Programs> findByStatusAndTour_Id(Status status,Long id);

    Programs findByStatusAndId(Status status, Long id);
}
