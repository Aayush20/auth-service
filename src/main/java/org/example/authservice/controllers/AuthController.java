package org.example.authservice.controllers;

import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.services.UserService;
import org.example.authservice.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthService authService;

    // Endpoint for user registration.
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody UserRegistrationDTO dto) {
        String result = userService.registerUser(dto);
        if(result.startsWith("Error:")) {
            return ResponseEntity.badRequest().body(result);
        }
        return ResponseEntity.ok(result);
    }

    // Token validation endpoint, called by the API Gateway.
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String token) {
        boolean valid = authService.validateToken(token);
        return ResponseEntity.ok(valid);
    }
}
