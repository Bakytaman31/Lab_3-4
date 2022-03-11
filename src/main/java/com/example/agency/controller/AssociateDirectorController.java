package com.example.agency.controller;

import com.example.agency.dto.*;
import com.example.agency.service.TourService;
import com.example.agency.service.UserImplService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("associate-director")
public class AssociateDirectorController {

    @Autowired
    private TourService tourService;

    @Autowired
    private UserImplService userImplService;


    @PostMapping("/add-employee")
    public ResponseMessage registrationEmployee(@RequestBody Employee employee){
        return userImplService.registrEmployee(employee);
    }

    @PostMapping("/add-tour")
    public ResponseMessage addTour(@RequestBody TourDto tourDto){
        return tourService.createTour(tourDto);
    }

    @GetMapping("/all-tours")
    public List<TourAllDto> getAllActiveTours(){
        return tourService.getAllActiveTours();
    }


    @DeleteMapping("delete-tour/{id}")
    public ResponseMessage deleteTour(@PathVariable Long id){
        return tourService.deleteTour(id);
    }

}
