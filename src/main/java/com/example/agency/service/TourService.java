package com.example.agency.service;

import com.example.agency.dto.*;
import com.example.agency.entities.Events;
import com.example.agency.entities.Programs;
import com.example.agency.entities.Tour;
import com.example.agency.enums.Status;
import com.example.agency.repositories.EventsRepository;
import com.example.agency.repositories.ProgramsRepository;
import com.example.agency.repositories.TourRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class TourService {

    @Autowired
    private TourRepository tourRepository;

    @Autowired
    private EventsRepository eventsRepository;

    @Autowired
    private ProgramsRepository programsRepository;

    @Transactional
    public ResponseMessage createTour(TourDto tourDto){
        Tour tour = new Tour();
        tour.setDateEnd(tourDto.getDateEnd());
        tour.setDescription(tourDto.getDescription());
        tour.setDateStart(tourDto.getDateStart());
        tour.setStatus(Status.ACTIVATE);
        tour.setName(tourDto.getName());
        return new ResponseMessage("successfully created!");
    }

    public ResponseMessage createEvent(EventsDto eventsDto){
        Events events = new Events();
        events.setName(eventsDto.getName());
        events.setStatus(Status.ACTIVATE);
        events.setDate(eventsDto.getDate());
        Tour tour = tourRepository.findByStatusAndId(Status.ACTIVATE,eventsDto.getTourId());
        if(tour == null){
            return new ResponseMessage("tour is null!");
        }
        events.setTour(tour);
        eventsRepository.save(events);
        return new ResponseMessage("successfully created!");
    }

    public ResponseMessage createProgram(ProgramDto programDto){
        Programs programs = new Programs();
        programs.setName(programDto.getName());
        programs.setStatus(Status.ACTIVATE);
        programs.setDate(programDto.getDate());
        programs.setAddress(programDto.getAddress());
        programs.setTime(programDto.getTime());
        Tour tour = tourRepository.findByStatusAndId(Status.ACTIVATE,programDto.getTourId());
        if(tour == null){
            return new ResponseMessage("tour is null!");
        }
        programs.setTour(tour);

        programsRepository.save(programs);

        return new ResponseMessage("successfully created!");
    }

    public List<TourAllDto> getAllActiveTours(){
        List<Tour> list = tourRepository.findByStatus(Status.ACTIVATE);
        List<TourAllDto> tourAllDtos = new ArrayList<>();
        for (Tour tour : list ) {
            TourAllDto tourDto = new TourAllDto();
            tourDto.setDescription(tour.getDescription());
            tourDto.setDateEnd(tour.getDateEnd());
            tourDto.setDateStart(tour.getDateStart());
            tourDto.setName(tour.getName());

            List<Programs> programs = programsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
            List<String> nameOfProgram = new ArrayList<>();
            for (Programs p : programs) {
                nameOfProgram.add(p.getName());
            }
            tourDto.setProgram(nameOfProgram);

            List<Events> events = eventsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
            List<String> nameOfEvents = new ArrayList<>();

            for(Events e : events){
                nameOfEvents.add(e.getName());
            }
            tourDto.setEvent(nameOfEvents);
            tourAllDtos.add(tourDto);
        }
        return tourAllDtos;
    }


    public ResponseMessage deleteTour(Long id){
        Tour tour = tourRepository.findByStatusAndId(Status.ACTIVATE,id);
        tour.setStatus(Status.REMOVED);
        List <Events> eventsList = eventsRepository.findByStatusAndTour_Id(Status.ACTIVATE,id);
        for(Events events : eventsList){
            events.setStatus(Status.REMOVED);
            eventsRepository.save(events);
        }

        List<Programs> programsList =programsRepository.findByStatusAndTour_Id(Status.ACTIVATE,id);
        for (Programs programs : programsList){
            programs.setStatus(Status.REMOVED);
            programsRepository.save(programs);
        }
        tourRepository.save(tour);
        return new ResponseMessage("successfully deleted!");
    }

    public TourAllDto getByNameTour(String name){
        Tour tour =tourRepository.findByNameAndStatus(name,Status.ACTIVATE);
        TourAllDto tourAllDto = new TourAllDto();

        tourAllDto.setName(tour.getName());
        tourAllDto.setDateEnd(tour.getDateEnd());
        tourAllDto.setDateStart(tour.getDateStart());
        List <Events> eventsList = eventsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
        List<String> nameOfEvents = new ArrayList<>();
        for (Events e : eventsList) {
            nameOfEvents.add(e.getName());
        }
        tourAllDto.setProgram(nameOfEvents);

        List<Programs> list =programsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
        List<String> nameOfProgram = new ArrayList<>();
        for (Programs p : list) {
            nameOfProgram.add(p.getName());
        }
        tourAllDto.setProgram(nameOfProgram);
        tourAllDto.setDescription(tour.getDescription());

        return tourAllDto;
    }

    public List<TourAllDto> getBookedTours(){
        List<Tour> list = tourRepository.findByStatus(Status.BOOKED);
        List<TourAllDto> allDtos  = new ArrayList<>();
        for (Tour tour : list){
            TourAllDto tourAllDto = new TourAllDto();
            tourAllDto.setDescription(tour.getDescription());
            List<Programs> listProgram =programsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
            List<String> nameOfProgram = new ArrayList<>();
            for (Programs p : listProgram) {
                nameOfProgram.add(p.getName());
            }
            tourAllDto.setProgram(nameOfProgram);
            List <Events> eventsList = eventsRepository.findByStatusAndTour_Id(Status.ACTIVATE,tour.getId());
            List<String> nameOfEvents = new ArrayList<>();
            for (Events e : eventsList) {
                nameOfEvents.add(e.getName());
            }
            tourAllDto.setProgram(nameOfEvents);
            tourAllDto.setName(tour.getName());
            tourAllDto.setDateStart(tour.getDateStart());
            tourAllDto.setDateEnd(tour.getDateEnd());
            allDtos.add(tourAllDto);
        }
        return allDtos;
    }


}
