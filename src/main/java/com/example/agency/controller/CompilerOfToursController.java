package com.example.agency.controller;

import com.example.agency.dto.EventsDto;
import com.example.agency.dto.ProgramDto;
import com.example.agency.dto.ResponseMessage;
import com.example.agency.service.TourService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("compiler-of-tours")
public class CompilerOfToursController {

    @Autowired
    private TourService tourService;


    @PostMapping("/create-program")
    public ResponseMessage createProgram(@RequestBody ProgramDto programDto){
        return tourService.createProgram(programDto);
    }


    @PostMapping("/create-event")
    public ResponseMessage createEvent(@RequestBody EventsDto eventsDto){
        return tourService.createEvent(eventsDto);
    }
}
