package com.example.agency.repositories;

import com.example.agency.entities.Position;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PositionRepository extends JpaRepository<Position,Long> {

    boolean existsByName(String name);
}
