package org.example.authservice.controllers;

import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody UserRegistrationDTO dto) {
        String response = userService.registerUser(dto);
        if (response.startsWith("Error:")) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }
}
