package com.example.agency.repositories;


import com.example.agency.entities.Events;
import com.example.agency.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EventsRepository extends JpaRepository<Events,Long> {

    List<Events> findByStatusAndTour_Id(Status status,Long id);

    Events findByStatusAndId(Status status,Long id);


}
