package com.example.demo.services;

import com.example.demo.jwt.JWTUtils;
import com.example.demo.model.LoginRequest;
import com.example.demo.model.LoginResponse;
import com.example.demo.model.SignUpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class UserServices {

    @Autowired
    private DataSource ds;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    public ResponseEntity<?> createUser(SignUpRequest signUpRequest) {

        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(ds);

        //  Check if user already exists
        if (manager.userExists(signUpRequest.getUserName())) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("username already exists");
        }

        // Create user
        manager.createUser(
                User.withUsername(signUpRequest.getUserName())
                        .password(encoder.encode(signUpRequest.getPassword()))
                        .roles(signUpRequest.getRole())
                        .build()
        );

        // Honest response
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("user created successfully");
    }


    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    loginRequest.getUsername()
                                    , loginRequest.getPassword()));
        } catch (AuthenticationException e) {
            Map<String, Object> map = new HashMap<>();
            map.put("msg", "Incorrect username or password");
            map.put("status", false);

            return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateJWTFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item ->item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse loginResponse = new LoginResponse(userDetails.getUsername(), roles, jwtToken);
        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }

    public ResponseEntity<?> getUserProfile() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();
        assert authentication != null;
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> map = new HashMap<>();
        map.put("username", userDetails.getUsername());
        map.put("roles", userDetails.getAuthorities()
                .stream()
                .map(item ->item.getAuthority())
                .collect(Collectors.toList())
        );


        return  ResponseEntity.ok(map);
    }
}
