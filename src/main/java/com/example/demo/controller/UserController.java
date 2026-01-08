package com.example.demo.controller;

import com.example.demo.model.LoginRequest;
import com.example.demo.model.SignUpRequest;
import com.example.demo.services.UserServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserServices userServices;

    @PostMapping("/signup")
    public ResponseEntity<?> createUser(@RequestBody SignUpRequest signUpRequest) {

        // 1. Validate nulls first (because Java is not your friend)
        if (signUpRequest.getUserName() == null ||
                signUpRequest.getPassword() == null ||
                signUpRequest.getRole() == null) {

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("username, password, and role are required");
        }

        // 2. Validate empties
        if (signUpRequest.getUserName().isBlank() ||
                signUpRequest.getPassword().isBlank() ||
                signUpRequest.getRole().isBlank()) {

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("fields cannot be empty");
        }
        // actual adding
        return userServices.createUser(signUpRequest);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        return userServices.authenticateUser(loginRequest);
    }


}