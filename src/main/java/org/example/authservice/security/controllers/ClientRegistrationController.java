package org.example.authservice.security.controllers;

import org.example.authservice.security.dtos.ClientRegistrationDTO;
import org.example.authservice.security.models.Client;
import org.example.authservice.security.services.ClientRegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/clients")
public class ClientRegistrationController {

    @Autowired
    private ClientRegistrationService clientRegistrationService;

    @PostMapping("/register")
    public ResponseEntity<?> registerClient(@RequestBody ClientRegistrationDTO registrationDTO) {
        try {
            Client client = clientRegistrationService.registerClient(registrationDTO);
            return ResponseEntity.ok("Client registered successfully with clientId: " + client.getClientId());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }
}

