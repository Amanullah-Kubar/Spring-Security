package com.example.demo.controller;

import com.example.demo.model.SignUpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    DataSource ds;

    @Autowired
    PasswordEncoder encoder;


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

        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(ds);

        // 3. Check if user already exists
        if (manager.userExists(signUpRequest.getUserName())) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("username already exists");
        }

        // 4. Create user
        manager.createUser(
                User.withUsername(signUpRequest.getUserName())
                        .password(encoder.encode(signUpRequest.getPassword()))
                        .roles(signUpRequest.getRole())
                        .build()
        );

        // 5. Honest response
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("user created successfully");
    }

}