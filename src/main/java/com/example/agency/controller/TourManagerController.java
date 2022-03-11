package com.example.agency.controller;

import com.example.agency.dto.*;
import com.example.agency.entities.Clients;
import com.example.agency.service.ClientService;
import com.example.agency.service.TicketsService;
import com.example.agency.service.TourService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tour-manager")
public class TourManagerController {

    @Autowired
    private TicketsService ticketsService;

    @Autowired
    private TourService tourService;

    @Autowired
    private ClientService clientService;

    @PostMapping("/create-client")
    public ResponseMessage createClient(@RequestBody Clients clients){
        return clientService.createClient(clients);
    }

    @PostMapping("/create-tour-contract-for-client/{phoneNumber}")
    public ResponseMessage createContractForClient(@RequestBody ContractForClient contractForClient,@PathVariable String phoneNumber){
        return ticketsService.createContract(contractForClient,phoneNumber);
    }

    @GetMapping("/get-by-tour-name/{name}")
    public TourAllDto getByTourName(@PathVariable String name){
        return tourService.getByNameTour(name);
    }

    @GetMapping("/all-booked-tours")
    public List<TourAllDto> getAllBooked(){
       return tourService.getBookedTours();
    }

    @GetMapping("/all-booked-tickets") // забронированные путевки
    public List<InfoAboutBookedTickets> getAllBookedTickets(){
        return ticketsService.getAllBookedTickets();
    }

}
