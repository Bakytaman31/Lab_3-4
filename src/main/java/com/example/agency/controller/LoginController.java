package com.example.agency.controller;

import com.example.agency.dto.AuthenticationResponse;
import com.example.agency.dto.UserDto;
import com.example.agency.dto.UserInfo;
import com.example.agency.security.JwtUtils;
import com.example.agency.service.UserImplService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("user")
public class LoginController {

    @Autowired
    private UserImplService userServiceImpl;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;



    @PostMapping("/auth")
    public ResponseEntity<AuthenticationResponse> auth(@RequestBody UserDto authDTO) {

            try {
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(authDTO.getEmail(),
                                authDTO.getPassword())
                );
            } catch (BadCredentialsException e) {
                return ResponseEntity.ok().body(new AuthenticationResponse("Не правильный логин или пароль!"));
            }
            return ResponseEntity.ok().body(new AuthenticationResponse("successfully"));
    }

    @GetMapping("/info")
    public UserInfo getInfo(){
        return userServiceImpl.getAuthorizedUser();
    }


}

