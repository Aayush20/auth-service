package org.example.authservice.security.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.example.authservice.security.dtos.ClientRegistrationDTO;
import org.example.authservice.security.models.Client;
import org.example.authservice.security.services.ClientRegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "OAuth2 Client Registration")
@RestController
@RequestMapping("/api/clients")
public class ClientRegistrationController {

    @Autowired
    private ClientRegistrationService clientRegistrationService;

    @Operation(summary = "Register new OAuth2 client")
    @PostMapping("/register")
    public ResponseEntity<?> registerClient(@Valid @RequestBody ClientRegistrationDTO registrationDTO) {
        try {
            Client client = clientRegistrationService.registerClient(registrationDTO);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("Client registered successfully with clientId: " + client.getClientId());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }
}
