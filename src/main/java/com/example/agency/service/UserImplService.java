package com.example.agency.service;

import com.example.agency.dto.*;
import com.example.agency.entities.User;
import com.example.agency.enums.Role;
import com.example.agency.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserImplService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) {

        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("Пользователь не найден!");
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(), user.getAuthorities());
    }


    public ResponseMessage  registrEmployee(Employee employee){
        User user = new User();
        if(!userRepository.existsByEmail(employee.getEmail())) {
            user.setRole(Role.EMPLOYEE);
            user.setEmail(employee.getEmail());
            user.setUserPassword(employee.getPassword());
            user.setFirstName(employee.getFirstname());
            user.setLastName(employee.getLastname());
            userRepository.save(user);
            return new ResponseMessage("успешно зарегистрирован!");
        }
        return new ResponseMessage("такой email существует!");
    }


    public User getCurrentUser(){
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        String userEmail= authentication.getName();
        return getByEmail(userEmail);
    }


    public User getByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public UserInfo getAuthorizedUser(){
        User user = getCurrentUser();
        UserInfo userInfo = new UserInfo();
        userInfo.setEmail(user.getEmail());
        userInfo.setRole(user.getRole().name());
        userInfo.setFirstname(user.getFirstName());
        userInfo.setLastname(user.getLastName());
        userInfo.setPhoneNumber(user.getPhoneNumber());
        return userInfo;
    }




}
