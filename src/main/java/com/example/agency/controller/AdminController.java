package com.example.agency.controller;


import com.example.agency.dto.PositionDto;
import com.example.agency.dto.ResponseMessage;
import com.example.agency.service.PositionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("admin")
public class AdminController {

    @Autowired
    private PositionService positionService;

    @PostMapping("/create-position")
    public ResponseMessage createPosition(@RequestBody PositionDto positionDto){
        return positionService.createPosition(positionDto);
    }
}
