package com.example.demo.controller;

import com.example.demo.jwt.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {


    @Autowired
    JWTUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/helloAdmin")
    public String greetAdmin() {
        return "Hello Admin";
    }


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/helloUser")
    public String greetUser() {
        return "Hello User";
    }

    @GetMapping("/greet")
    public String greet() {
        return ("GreetingController");
    }


}
