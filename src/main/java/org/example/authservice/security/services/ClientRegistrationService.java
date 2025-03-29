package org.example.authservice.security.services;


import org.example.authservice.security.dtos.ClientRegistrationDTO;
import org.example.authservice.security.models.Client;
import org.example.authservice.security.repositories.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class ClientRegistrationService {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String serializeList(java.util.List<String> list) {
        return list != null ? String.join(",", list) : null;
    }

    public Client registerClient(ClientRegistrationDTO registrationDTO) {
        // Check for an existing client - if it exists, you might throw an exception.
        clientRepository.findByClientId(registrationDTO.getClientId())
                .ifPresent(existing -> {
                    throw new IllegalArgumentException("Client with this clientId already exists.");
                });

        Client client = new Client();
        client.setId(UUID.randomUUID().toString());
        client.setClientId(registrationDTO.getClientId());
        client.setClientName(registrationDTO.getClientName());
        client.setClientIdIssuedAt(Instant.now());
        // Encrypt the client secret
        client.setClientSecret(passwordEncoder.encode(registrationDTO.getClientSecret()));
        // You can set clientSecretExpiresAt if you want an expiry date

        // Serialize list fields as comma-separated strings
        client.setClientAuthenticationMethods(serializeList(registrationDTO.getClientAuthenticationMethods()));
        client.setAuthorizationGrantTypes(serializeList(registrationDTO.getAuthorizationGrantTypes()));
        client.setRedirectUris(serializeList(registrationDTO.getRedirectUris()));
        client.setPostLogoutRedirectUris(serializeList(registrationDTO.getPostLogoutRedirectUris()));
        client.setScopes(serializeList(registrationDTO.getScopes()));

        // Optionally, store JSON strings if you need to support more complex settings.
        client.setClientSettings(registrationDTO.getClientSettings());
        client.setTokenSettings(registrationDTO.getTokenSettings());

        return clientRepository.save(client);
    }
}

