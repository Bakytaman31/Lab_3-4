package com.example.agency.service;

import com.example.agency.dto.ContractForClient;
import com.example.agency.dto.InfoAboutBookedTickets;
import com.example.agency.dto.ResponseMessage;
import com.example.agency.entities.*;
import com.example.agency.enums.Status;
import com.example.agency.repositories.AirlineRepository;
import com.example.agency.repositories.ClientRepository;
import com.example.agency.repositories.TicketsRepository;
import com.example.agency.repositories.TourRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class TicketsService {

    @Autowired
    private TicketsRepository ticketsRepository;

    @Autowired
    private AirlineRepository airlineRepository;

    @Autowired
    private TourRepository tourRepository;

    @Autowired
    private UserImplService userImplService;

    @Autowired
    private ClientRepository clientRepository;


    public ResponseMessage createContract(ContractForClient contractForClient,String phoneNumber){
        Tickets tickets = new Tickets();
        Airline airline = airlineRepository.findById(contractForClient.getAirlineId()).orElse(null);
        if(airline == null)
            return new ResponseMessage("airline is null");
        tickets.setAirline(airline);
        tickets.setUser(userImplService.getCurrentUser());
        tickets.setPlace(contractForClient.getPlace());
        LocalDateTime localDateTime = LocalDateTime.now();
        tickets.setDateOfRegistration(convertLocalDateTimeToDateUsingInstant(localDateTime));
        tickets.setStatus(Status.BOOKED);
        Tour tour = tourRepository.findByStatusAndId(Status.ACTIVATE,contractForClient.getTourId());
        if(tour ==null)
            return new ResponseMessage("tour is null");
        tickets.setTour(tour);
        tour.setStatus(Status.BOOKED);
        Clients clients = clientRepository.findByPhoneNumber(phoneNumber);
        if(clients == null)
            return new ResponseMessage("client is null");
        tickets.setClients(clients);
        ticketsRepository.save(tickets);

        return new ResponseMessage("successfully booked!");
    }

    Date convertLocalDateTimeToDateUsingInstant(LocalDateTime dateToConvert) {
        return java.util.Date
                .from(dateToConvert.atZone(ZoneId.systemDefault())
                        .toInstant());
    }


    public List<InfoAboutBookedTickets> getAllBookedTickets(){ //все забронированные путевки (путевки включают билеты в самолет)

        List<Tickets> ticketsList = ticketsRepository.findByStatus(Status.BOOKED);
        List<InfoAboutBookedTickets> infoAboutBookedTickets = new ArrayList<>();
        for (Tickets tickets : ticketsList){
            InfoAboutBookedTickets ticketDto  = new InfoAboutBookedTickets();
            ticketDto.setAirline(tickets.getAirline().getName());
            ticketDto.setTour(tickets.getTour().getName());
            ticketDto.setPlace(tickets.getPlace());
            ticketDto.setDateOfRegistration(tickets.getDateOfRegistration());
            ticketDto.setNameClient(tickets.getClients().getFirstname());
            ticketDto.setPhoneNumClient(tickets.getClients().getPhoneNumber());
            infoAboutBookedTickets.add(ticketDto);
        }
        return infoAboutBookedTickets;
    }



}
