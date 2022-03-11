package com.example.agency.service;


import com.example.agency.dto.ResponseMessage;
import com.example.agency.entities.Clients;
import com.example.agency.repositories.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ClientService {

    @Autowired
    private ClientRepository clientRepository;

    public ResponseMessage createClient(Clients clients){
        if(!clientRepository.existsByPhoneNumber(clients.getPhoneNumber())) {
            clients.setAddress(clients.getAddress());
            clients.setFirstname(clients.getFirstname());
            clients.setLastname(clients.getLastname());
            clients.setPassport(clients.getPassport());
            clients.setPhoneNumber(clients.getPhoneNumber());
            clientRepository.save(clients);
            return new ResponseMessage("successfully added!");
        }
        return new ResponseMessage("error added!");
    }

}
