package com.example.agency.service;

import com.example.agency.dto.PositionDto;
import com.example.agency.dto.ResponseMessage;
import com.example.agency.entities.Position;
import com.example.agency.repositories.PositionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PositionService {

    @Autowired
    private PositionRepository positionRepository;

    public ResponseMessage createPosition(PositionDto positionDto){
        if(!positionRepository.existsByName(positionDto.getName())) {
            Position position = new Position();
            position.setName(positionDto.getName());
            positionRepository.save(position);
            return new ResponseMessage("successfully created!");
        }

        return new ResponseMessage("position not created!");
    }


}
